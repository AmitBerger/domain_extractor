import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import subprocess

# Set initial appearance mode and theme
ctk.set_appearance_mode("System")  
ctk.set_default_color_theme("green")  

class DomainExtractorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Domain Extractor")
        self.geometry("700x600")
        self.resizable(False, False)

        # Appearance Mode and Theme Selection
        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.pack(pady=10, padx=20, fill="x")

        self.appearance_label = ctk.CTkLabel(self.top_frame, text="Appearance Mode:")
        self.appearance_label.pack(side="left", padx=(10, 5))

        self.appearance_option = ctk.CTkOptionMenu(self.top_frame, values=["System", "Light", "Dark"],
                                                   command=self.change_appearance_mode)
        self.appearance_option.set("System")
        self.appearance_option.pack(side="left", padx=(0, 20))

        self.theme_label = ctk.CTkLabel(self.top_frame, text="Theme:")
        self.theme_label.pack(side="left", padx=(10, 5))

        self.theme_option = ctk.CTkOptionMenu(self.top_frame, values=["green", "blue", "dark-blue"],
                                              command=self.change_theme)
        self.theme_option.set("green")
        self.theme_option.pack(side="left")

        # URL Entry Frame
        self.url_frame = ctk.CTkFrame(self)
        self.url_frame.pack(pady=10, padx=20, fill="x")

        self.url_label = ctk.CTkLabel(self.url_frame, text="Enter URL:")
        self.url_label.pack(side="left", padx=(10, 5))

        self.url_entry = ctk.CTkEntry(self.url_frame, width=400)
        self.url_entry.pack(side="left", padx=(0, 10))

        self.extract_url_button = ctk.CTkButton(self.url_frame, text="Extract from URL", command=self.extract_from_url,
                                                corner_radius=10)
        self.extract_url_button.pack(side="left")

        # File Selection Button
        self.file_button = ctk.CTkButton(self, text="Select Text Files", command=self.extract_from_files,
                                         corner_radius=10)
        self.file_button.pack(pady=10)

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self, width=650)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

        # Results Textbox
        self.result_label = ctk.CTkLabel(self, text="Results:")
        self.result_label.pack(pady=(20, 5))

        self.result_text = ctk.CTkTextbox(self, width=650, height=300)
        self.result_text.pack(padx=20, pady=(0, 20))

        # Status Bar
        self.status_bar = ctk.CTkLabel(self, text="Ready", anchor="w")
        self.status_bar.pack(fill="x", side="bottom")
                # Conclusions Label
        self.conclusions_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=14, weight="bold"))
        self.conclusions_label.pack(pady=(0, 10))


    def change_appearance_mode(self, new_mode):
        ctk.set_appearance_mode(new_mode)

    def change_theme(self, new_theme):
        ctk.set_default_color_theme(new_theme)

    def extract_from_url(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL.")
            return
        with open("temp_input.txt", "w", encoding="utf-8") as f:
            f.write(url)
        self.run_extraction("temp_input.txt")

    def extract_from_files(self):
        file_paths = filedialog.askopenfilenames(
            title="Select Text Files",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_paths:
            combined_input = "combined_input.txt"
            try:
                with open(combined_input, "w", encoding="utf-8") as outfile:
                    for file_path in file_paths:
                        with open(file_path, "r", encoding="utf-8") as infile:
                            outfile.write(infile.read() + "\n")
                self.run_extraction(combined_input)
            except Exception as e:
                messagebox.showerror("Error", f"Error reading files: {e}")

    def run_extraction(self, input_file):
        output_file = "output.txt"
        try:
            self.status_bar.configure(text="Processing...")
            self.progress_bar.set(0.5)
            self.update_idletasks()

            subprocess.run(["python", "domain_extractor.py", input_file, output_file], check=True)

            self.progress_bar.set(1.0)
            self.status_bar.configure(text="Completed")

            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    results = f.read()
                self.result_text.delete("1.0", "end")
                self.result_text.insert("end", results)
            else:
                messagebox.showerror("Error", "No results found.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error running the script: {e}")
            self.status_bar.configure(text="Error")
            self.progress_bar.set(0)
        finally:
            self.after(2000, lambda: self.status_bar.configure(text="Ready"))
            self.after(2000, lambda: self.progress_bar.set(0))

if __name__ == "__main__":
    app = DomainExtractorApp()
    app.mainloop()
