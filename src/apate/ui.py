import rich
from rich import console, panel


class UI:
    def __init__(self):
        self.console = console.Console()

    def display_banner(self):
        banner = """
        █████╗ ██████╗  █████╗ ████████╗███████╗
        ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
        ███████║██████╔╝███████║   ██║   █████╗  
        ██╔══██║██╔═══╝ ██╔══██║   ██║   ██╔══╝  
        ██║  ██║██║     ██║  ██║   ██║   ███████╗
        ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝
        """
        rich.print(banner)

    def get_main_menu_choice(self) -> int:
        self.console.print("[cyan]1.[/cyan] Encrypt a file ")
        self.console.print("[cyan]2.[/cyan] Decrypt a file ")
        choice = self.console.input("[cyan]Enter your choice (1 or 2): [/cyan]")
        return int(choice) if choice in ["1", "2"] else 0
    
    def get_encryption_algo_choice(self) -> int:
        self.console.print("[cyan]1.[/cyan] AES-256-GCM + RSA-OAEP")
        self.console.print("[cyan]2.[/cyan] ChaCha20-Poly1305 + RSA-OAEP")
        choice = self.console.input("[bold yellow]> [/bold yellow]")
        return int(choice) if choice.isdigit() else 0     
    
    def get_input_path(self):
        return self.console.input(
            "Enter the path of the file or directory to encrypt: "
        )
    def get_decrypt_input_path(self):
        return self.console.input(
            "[bold yellow]Enter the path of the .veil file to decrypt: [/bold yellow]"
        )

    def display_success_message(self, message):
        self.console.print(panel.Panel(message, title="Success", style="green"))

    def display_error_message(self, message):
        self.console.print(panel.Panel(message, title="Error", style="red"))
