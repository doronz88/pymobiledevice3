import click


@click.group()
def cli():
    """ version cli """
    pass


@cli.command()
def version():
    """ get installed package version """
    try:
        from pymobiledevice3._version import __version__
        print(__version__)
    except ImportError:
        print('version could not be determined. please first install/build the package')
