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

    def get_input_path(self):
        return self.console.input(
            "Enter the path of the file or directory to encrypt: "
        )

    def display_success_message(self, message):
        self.console.print(panel.Panel(message, title="Success", style="green"))

    def display_error_message(self, message):
        self.console.print(panel.Panel(message, title="Error", style="red"))
