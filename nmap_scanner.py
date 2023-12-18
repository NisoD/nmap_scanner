import click
import subprocess 

@click.command()
@click.argument('ip_address')
def nmap_args(ip_address):
    try: #run subprocess and print
        result = subprocess.run(['nmap', ip_address], capture_output=True, text=True, check=True)
        click.echo(result.stdout)
    except subprocess.CalledProcessError as e:
        # Error handler
        click.echo(f"Error: {e}")
        click.echo(f"Command output: {e.output}")

if __name__ == '__main__':
    nmap_args()