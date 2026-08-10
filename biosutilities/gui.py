#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2026 Plato Mavropoulos
"""

import contextlib
import io
import os
import queue
import subprocess
import threading
import tkinter as tk

from tkinter import filedialog, messagebox, ttk
from typing import Final

from biosutilities import __version__
from biosutilities.__main__ import get_utilities_classes
from biosutilities.common.externals import get_external_path
from biosutilities.common.paths import (
    delete_dirs, extract_folder, is_dir_read, is_empty_dir, is_file_read, path_files, path_name, real_path
)
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import to_boxed, to_ordinal


EXTERNALS: Final[dict[str, str | list[str]]] = {
    '7-Zip': ['7zzs', '7zz', '7z'],
    'UEFIFind': ['uefifind', 'UEFIFind'],
    'UEFIExtract': ['uefiextract', 'UEFIExtract'],
    'TianoCompress': ['TianoCompress', 'tianocompress'],
    'ToshibaComExtractor': ['comextract', 'ComExtract'],
}


class QueueWriter(io.TextIOBase):
    """ Redirect print output to the Tk event queue. """

    def __init__(self, log_queue: queue.Queue[str]) -> None:
        self.log_queue = log_queue

    def write(self, text: str) -> int:
        if text:
            self.log_queue.put(text)

        return len(text)

    def flush(self) -> None:
        return None


class BIOSUtilitiesGui(tk.Tk):
    """ Tkinter GUI for BIOSUtilities. """

    MAX_FAT32_ITEMS: Final[int] = 65535

    def __init__(self) -> None:
        super().__init__()

        self.title(f'BIOSUtilities v{__version__}')
        self.geometry('980x680')
        self.minsize(760, 540)

        self.input_paths: list[str] = []
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.worker_thread: threading.Thread | None = None
        self.last_output_path: str = ''
        self.utility_classes: list[type[BIOSUtility]] = get_utilities_classes()

        self.output_var = tk.StringVar(value=os.getcwd())
        self.utility_var = tk.StringVar(value='Auto detect')
        self.status_var = tk.StringVar(value='Ready')
        self.progress_var = tk.DoubleVar(value=0)

        self._build_widgets()
        self._refresh_external_status()
        self.after(100, self._drain_log_queue)

    def _build_widgets(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        input_frame = ttk.LabelFrame(self, text='Input')
        input_frame.grid(row=0, column=0, sticky='nsew', padx=10, pady=(10, 6))
        input_frame.columnconfigure(0, weight=1)

        self.input_list = tk.Listbox(input_frame, height=6, selectmode=tk.EXTENDED)
        self.input_list.grid(row=0, column=0, rowspan=4, sticky='nsew', padx=(8, 6), pady=8)
        input_scroll = ttk.Scrollbar(input_frame, command=self.input_list.yview)
        input_scroll.grid(row=0, column=1, rowspan=4, sticky='ns', pady=8)
        self.input_list.configure(yscrollcommand=input_scroll.set)

        ttk.Button(input_frame, text='Add files', command=self._add_files).grid(row=0, column=2, sticky='ew', padx=8, pady=(8, 2))
        ttk.Button(input_frame, text='Add folder', command=self._add_folder).grid(row=1, column=2, sticky='ew', padx=8, pady=2)
        ttk.Button(input_frame, text='Remove', command=self._remove_selected).grid(row=2, column=2, sticky='ew', padx=8, pady=2)
        ttk.Button(input_frame, text='Clear', command=self._clear_inputs).grid(row=3, column=2, sticky='ew', padx=8, pady=(2, 8))

        options_frame = ttk.LabelFrame(self, text='Options')
        options_frame.grid(row=1, column=0, sticky='ew', padx=10, pady=6)
        options_frame.columnconfigure(1, weight=1)

        ttk.Label(options_frame, text='Output').grid(row=0, column=0, sticky='w', padx=(8, 6), pady=8)
        ttk.Entry(options_frame, textvariable=self.output_var).grid(row=0, column=1, sticky='ew', pady=8)
        ttk.Button(options_frame, text='Browse', command=self._choose_output).grid(row=0, column=2, sticky='ew', padx=8, pady=8)
        ttk.Button(options_frame, text='Open', command=self._open_output).grid(row=0, column=3, sticky='ew', padx=(0, 8), pady=8)

        ttk.Label(options_frame, text='Utility').grid(row=1, column=0, sticky='w', padx=(8, 6), pady=(0, 8))
        utility_names = ['Auto detect', *[utility.__name__ for utility in self.utility_classes]]
        ttk.Combobox(options_frame, textvariable=self.utility_var, values=utility_names, state='readonly').grid(
            row=1, column=1, sticky='ew', pady=(0, 8)
        )
        self.run_button = ttk.Button(options_frame, text='Run extraction', command=self._start_extraction)
        self.run_button.grid(row=1, column=2, columnspan=2, sticky='ew', padx=8, pady=(0, 8))

        log_frame = ttk.LabelFrame(self, text='Log')
        log_frame.grid(row=2, column=0, sticky='nsew', padx=10, pady=6)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, wrap='none', font=('Consolas', 10), undo=False)
        self.log_text.grid(row=0, column=0, sticky='nsew', padx=(8, 0), pady=8)
        log_y = ttk.Scrollbar(log_frame, orient='vertical', command=self.log_text.yview)
        log_y.grid(row=0, column=1, sticky='ns', pady=8)
        log_x = ttk.Scrollbar(log_frame, orient='horizontal', command=self.log_text.xview)
        log_x.grid(row=1, column=0, sticky='ew', padx=(8, 0), pady=(0, 8))
        self.log_text.configure(yscrollcommand=log_y.set, xscrollcommand=log_x.set)

        bottom_frame = ttk.Frame(self)
        bottom_frame.grid(row=3, column=0, sticky='ew', padx=10, pady=(6, 10))
        bottom_frame.columnconfigure(1, weight=1)

        ttk.Button(bottom_frame, text='Check tools', command=self._refresh_external_status).grid(row=0, column=0, sticky='w')
        ttk.Progressbar(bottom_frame, variable=self.progress_var, maximum=100).grid(row=0, column=1, sticky='ew', padx=10)
        ttk.Button(bottom_frame, text='Clear log', command=self._clear_log).grid(row=0, column=2, sticky='e')
        ttk.Button(bottom_frame, text='Save log', command=self._save_log).grid(row=0, column=3, sticky='e', padx=(6, 10))
        ttk.Label(bottom_frame, textvariable=self.status_var).grid(row=0, column=4, sticky='e')

    def _add_files(self) -> None:
        for input_path in filedialog.askopenfilenames(title='Select BIOS update files'):
            self._add_input_path(input_path)

    def _add_folder(self) -> None:
        input_path = filedialog.askdirectory(title='Select folder with BIOS update files')

        if input_path:
            self._add_input_path(input_path)

    def _add_input_path(self, input_path: str) -> None:
        input_path_real = real_path(in_path=input_path)

        if input_path_real not in self.input_paths:
            self.input_paths.append(input_path_real)
            self.input_list.insert(tk.END, input_path_real)

    def _remove_selected(self) -> None:
        for index in reversed(self.input_list.curselection()):
            del self.input_paths[index]
            self.input_list.delete(index)

    def _clear_inputs(self) -> None:
        self.input_paths.clear()
        self.input_list.delete(0, tk.END)

    def _choose_output(self) -> None:
        output_path = filedialog.askdirectory(title='Select extraction output folder')

        if output_path:
            self.output_var.set(real_path(in_path=output_path))

    def _open_output(self) -> None:
        output_path = self.last_output_path or self.output_var.get()

        if not is_dir_read(in_path=output_path):
            messagebox.showwarning('Output folder', 'Output folder does not exist or is not readable.')
            return

        if os.name == 'nt':
            os.startfile(output_path)  # pylint: disable=no-member
        else:
            subprocess.Popen(['open' if os.uname().sysname == 'Darwin' else 'xdg-open', output_path])

    def _refresh_external_status(self) -> None:
        self._append_log(f'BIOSUtilities v{__version__}\nExternal tools:\n')

        missing = 0

        for title, commands in EXTERNALS.items():
            try:
                tool_path = get_external_path(cmd=commands)
                self._append_log(f'  OK      {title}: {tool_path}\n')
            except OSError:
                missing += 1
                self._append_log(f'  Missing {title}\n')

        self._append_log('\n')
        self.status_var.set('Ready' if not missing else f'Ready, {missing} external tool(s) missing')

    def _clear_log(self) -> None:
        self.log_text.delete('1.0', tk.END)

    def _save_log(self) -> None:
        log_path = filedialog.asksaveasfilename(
            title='Save log',
            defaultextension='.txt',
            filetypes=(('Text files', '*.txt'), ('All files', '*.*'))
        )

        if log_path:
            with open(log_path, 'w', encoding='utf-8') as log_file:
                log_file.write(self.log_text.get('1.0', tk.END))

    def _start_extraction(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            return

        input_files = self._collect_input_files()

        if not input_files:
            messagebox.showwarning('Input required', 'Add at least one readable file or folder.')
            return

        output_path = real_path(in_path=self.output_var.get())

        if not is_dir_read(in_path=output_path):
            messagebox.showwarning('Output required', 'Choose a readable output folder.')
            return

        self.last_output_path = output_path
        utility_classes = self._selected_utilities()
        self.progress_var.set(0)
        self.run_button.configure(state=tk.DISABLED)
        self.status_var.set('Running')
        self._append_log(f'Starting extraction: {len(input_files)} file(s)\n\n')

        self.worker_thread = threading.Thread(
            target=self._run_extraction,
            args=(input_files, output_path, utility_classes),
            daemon=True
        )
        self.worker_thread.start()

    def _collect_input_files(self) -> list[str]:
        input_files: list[str] = []

        for input_path in self.input_paths:
            if is_dir_read(in_path=input_path):
                input_files.extend(path_files(in_path=input_path))
            elif is_file_read(in_path=input_path):
                input_files.append(input_path)

        return list(dict.fromkeys(input_files))

    def _selected_utilities(self) -> list[type[BIOSUtility]]:
        selected = self.utility_var.get()

        if selected == 'Auto detect':
            return self.utility_classes

        return [utility for utility in self.utility_classes if utility.__name__ == selected]

    def _run_extraction(self, input_files: list[str], output_path: str, utility_classes: list[type[BIOSUtility]]) -> None:
        parsed_count = 0

        try:
            with contextlib.redirect_stdout(QueueWriter(self.log_queue)):
                for input_index, input_file in enumerate(input_files, start=1):
                    input_name = path_name(in_path=input_file, limit=True)
                    printer(message=f'{to_boxed(in_text=input_name)}\n')

                    for utility_class in utility_classes:
                        extract_path = self._available_extract_path(output_path=output_path, input_name=input_name)
                        utility = utility_class(input_object=input_file, extract_path=extract_path, padding=8)

                        if not utility.check_format():
                            continue

                        printer(message=to_boxed(in_text=f'{utility.TITLE} v{__version__}'), new_line=False, padding=4)
                        is_parsed_format = utility.parse_format()
                        is_empty_output = is_empty_dir(in_path=extract_path)

                        if is_empty_output:
                            delete_dirs(in_path=extract_path)

                        if is_parsed_format and not is_empty_output:
                            parsed_count += 1
                            break
                    else:
                        printer(message='No supported utility detected this file.', padding=4)

                    self.log_queue.put(f'__PROGRESS__:{input_index}:{len(input_files)}')

            self.log_queue.put(f'\nDone. Extracted {parsed_count}/{len(input_files)} file(s).\n')
        except Exception as error:  # pylint: disable=broad-except
            self.log_queue.put(f'\nError: {error}\n')
        finally:
            self.log_queue.put('__DONE__')

    def _available_extract_path(self, output_path: str, input_name: str) -> str:
        extract_path = os.path.join(output_path, extract_folder(in_path=input_name))

        if is_dir_read(in_path=extract_path):
            for suffix in range(2, self.MAX_FAT32_ITEMS):
                renamed_path = f'{os.path.normpath(extract_path)}_{to_ordinal(in_number=suffix)}'

                if not is_dir_read(in_path=renamed_path):
                    return renamed_path

        return extract_path

    def _drain_log_queue(self) -> None:
        while True:
            try:
                text = self.log_queue.get_nowait()
            except queue.Empty:
                break

            if text == '__DONE__':
                self.run_button.configure(state=tk.NORMAL)
                self.status_var.set('Done')
            elif text.startswith('__PROGRESS__:'):
                _, done, total = text.split(':')
                self.progress_var.set(int(done) / int(total) * 100)
                self.status_var.set(f'Processed {done}/{total}')
            else:
                self._append_log(text)

        self.after(100, self._drain_log_queue)

    def _append_log(self, text: str) -> None:
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)


def main() -> None:
    """ Launch GUI. """

    BIOSUtilitiesGui().mainloop()


if __name__ == '__main__':
    main()
