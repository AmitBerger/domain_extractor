"""
Domain Extractor GUI Application
================================

This GUI allows users to extract domains from URLs or text files using a separate
Python script (domain_extractor.py). The interface is built using customtkinter
for modern aesthetics and supports appearance mode and theme switching.

Features:
- Accepts URL input for domain extraction.
- Allows selection of multiple text files containing URLs.
- Displays extracted results in a styled output box.
- Shows input summary and processing progress.
- Supports system, light, and dark modes.
- Allows theme selection (limited to built-in themes).

Dependencies:
- customtkinter
- tkinter
- subprocess, os (standard)
- domain_extractor.py (external script for domain extraction)
"""

import customtkinter as ctk
import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox

# === Initialize global appearance and theme ===
ctk.set_appearance_mode("System")  # Options: "System", "Light", "Dark"


class DomainExtractorApp(ctk.CTk):
    """
    Main application window for the domain extractor.
    Handles UI setup, user interaction, and subprocess calls to domain_extractor.py
    """

    def __init__(self):
        super().__init__()

        # === Window Setup ===
        self.title("Domain Extractor")
        self.geometry("700x600")
        self.resizable(False, False)

        # === Appearance & Theme Controls ===
        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.pack(pady=10, padx=20, fill="x")

        self.appearance_label = ctk.CTkLabel(self.top_frame, text="Appearance Mode:")
        self.appearance_label.pack(side="left", padx=(10, 5))

        self.appearance_option = ctk.CTkOptionMenu(
            self.top_frame,
            values=["System", "Light", "Dark"],
            command=self.change_appearance_mode,
        )
        self.appearance_option.set("System")
        self.appearance_option.pack(side="left", padx=(0, 20))

        self.theme_label = ctk.CTkLabel(self.top_frame, text="Theme:")
        self.theme_label.pack(side="left", padx=(10, 5))

        self.theme_option = ctk.CTkOptionMenu(
            self.top_frame,
            values=["blue", "green"],
            command=self.change_theme,  # Not working for now
        )
        self.theme_option.set("blue")
        self.theme_option.pack(side="left")

        # === URL Input Section ===
        self.url_frame = ctk.CTkFrame(self)
        self.url_frame.pack(pady=10, padx=20, fill="x")

        self.url_label = ctk.CTkLabel(self.url_frame, text="Enter URL:")
        self.url_label.pack(side="left", padx=(10, 5))

        self.url_entry = ctk.CTkEntry(self.url_frame, width=400)
        self.url_entry.pack(side="left", padx=(0, 10))

        self.extract_url_button = ctk.CTkButton(
            self.url_frame,
            text="Extract from URL",
            command=self.extract_from_url,
            corner_radius=10,
        )
        self.extract_url_button.pack(side="left")

        # === File Upload Button ===
        self.file_button = ctk.CTkButton(
            self,
            text="Select Text Files",
            command=self.extract_from_files,
            corner_radius=10,
        )
        self.file_button.pack(pady=10)

        # === Progress Bar ===
        self.progress_bar = ctk.CTkProgressBar(self, width=650)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

        # === Input Information Label ===
        self.input_info_label = ctk.CTkLabel(self, text="", anchor="w")
        self.input_info_label.pack(padx=20, pady=(0, 5), fill="x")

        # === Results Section ===
        self.result_label = ctk.CTkLabel(self, text="Results:")
        self.result_label.pack(pady=(10, 5))

        # Use a plain tk.Text to allow colored tags
        self.result_text = tk.Text(self, width=80, height=18, bd=0, wrap="none")
        self.result_text.pack(padx=20, pady=(0, 20), fill="both", expand=True)
        # VT status tags
        self.result_text.tag_configure(
            "malicious", foreground="red", font=("TkDefaultFont", 10, "bold")
        )
        self.result_text.tag_configure(
            "suspicious", foreground="orange", font=("TkDefaultFont", 10, "bold")
        )
        self.result_text.tag_configure(
            "clean", foreground="green", font=("TkDefaultFont", 10, "bold")
        )

        # === Download Output.txt Button ===
        self.download_button = ctk.CTkButton(
            self,
            text="Download output.txt",
            command=self.download_output_file,
            corner_radius=10,
            state="disabled",
        )
        self.download_button.pack(pady=(0, 10))

        # === Status Bar ===
        self.status_bar = ctk.CTkLabel(self, text="Ready", anchor="w")
        self.status_bar.pack(fill="x", side="bottom")

        # === Optional conclusions label (unused but reserved) ===
        self.conclusions_label = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=14, weight="bold")
        )
        self.conclusions_label.pack(pady=(0, 10))

    # === Theme and Appearance Methods ===

    def change_appearance_mode(self, new_mode):
        """Changes the GUI appearance mode (Light, Dark, or System default)."""
        ctk.set_appearance_mode(new_mode)

    def change_theme(self, new_theme):
        """
        Applies a different color theme.
        Limited to themes included in customtkinter (e.g., 'blue', 'green').
        """
        try:
            ctk.set_default_color_theme(new_theme)
        except Exception as e:
            messagebox.showerror("Theme Error", f"Could not apply theme: {e}")

    # === Domain Extraction Methods ===

    def extract_from_url(self):
        """
        Called when user clicks 'Extract from URL'.
        Writes URL to a temporary file and runs the extraction.
        """
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL.")
            return

        # Write URL to temporary input file
        with open("temp_input.txt", "w", encoding="utf-8") as f:
            f.write(url)

        # Show input info and clear result box
        self.input_info_label.configure(text=f"Input URL: {url}")
        self.result_text.delete("1.0", "end")

        # Start extraction
        self.run_extraction("temp_input.txt")

    def extract_from_files(self):
        """
        Called when user selects files.
        Combines contents of selected text files and runs extraction.
        """
        if file_paths := filedialog.askopenfilenames(
            title="Select Text Files",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        ):
            combined_input = "combined_input.txt"
            try:
                # Combine all selected files into one
                with open(combined_input, "w", encoding="utf-8") as outfile:
                    for file_path in file_paths:
                        with open(file_path, "r", encoding="utf-8") as infile:
                            outfile.write(infile.read() + "\n")

                # Show file names and clear results
                filenames = [os.path.basename(path) for path in file_paths]
                self.input_info_label.configure(
                    text=f"Uploaded files: {', '.join(filenames)}"
                )
                self.result_text.delete("1.0", "end")

                self.run_extraction(combined_input)
            except Exception as e:
                messagebox.showerror("Error", f"Error reading files: {e}")

    def run_extraction(self, input_file):
        """
        Runs the external domain_extractor.py script on the given input file.
        Displays output in the GUI and updates status/progress bars.
        """
        output_file = "output.txt"
        try:
            self._set_processing_state()

            self._run_domain_extractor_subprocess(input_file, output_file)

            self.progress_bar.set(1.0)
            self.status_bar.configure(text="Completed")

            if os.path.exists(output_file):
                # Read & display with color tags
                with open(output_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                self.result_text.delete("1.0", "end")
                for line in lines:
                    # Remove ASN info for GUI display
                    line_wo_asn = line
                    if " ASN:" in line:
                        line_wo_asn = line.split(" ASN:")[0] + "\n"
                    vt_tag = None
                    vt_str = None
                    for tag in ("malicious", "suspicious", "clean"):
                        vt_marker = f"VT:{tag}"
                        if vt_marker in line_wo_asn:
                            vt_tag = tag
                            vt_str = vt_marker
                            break
                    if vt_tag and vt_str:
                        vt_index = line_wo_asn.find(vt_str)
                        # Insert text before VT:
                        self.result_text.insert("end", line_wo_asn[:vt_index])
                        # Insert VT:... with color tag
                        self.result_text.insert("end", vt_str, vt_tag)
                        # Insert the rest of the line
                        self.result_text.insert(
                            "end", line_wo_asn[vt_index + len(vt_str) :]
                        )
                    else:
                        self.result_text.insert("end", line_wo_asn)
                self.download_button.configure(state="normal")
            else:
                messagebox.showerror("Error", "No results found.")
                self.download_button.configure(state="disabled")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error running the script: {e}")
            self.status_bar.configure(text="Error")
            self.progress_bar.set(0)
            self.download_button.configure(state="disabled")
        finally:
            # Reset after delay
            self.after(2000, lambda: self.status_bar.configure(text="Ready"))
            self.after(2000, lambda: self.progress_bar.set(0))

    def download_output_file(self):
        """
        Opens a file dialog to save a copy of output.txt.
        """
        output_file = "output.txt"
        if not os.path.exists(output_file):
            messagebox.showerror("Error", "No output.txt file found.")
            return
        if save_path := filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile="output.txt",
        ):
            try:
                with open(output_file, "rb") as src, open(save_path, "wb") as dst:
                    dst.write(src.read())
                messagebox.showinfo("Success", f"Saved as {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")

    def _set_processing_state(self):
        self.status_bar.configure(text="Processing...")
        self.progress_bar.set(0.5)
        self.update_idletasks()

    def _run_domain_extractor_subprocess(self, input_file, output_file):
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        cmd = ["python", "domain_extractor.py", input_file, output_file]
        if vt_key:
            cmd.append(vt_key)
        subprocess.run(cmd, check=True)


# === Run application ===
if __name__ == "__main__":
    app = DomainExtractorApp()
    app.mainloop()
