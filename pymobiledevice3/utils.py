def plist_access_path(d, path: tuple, type_=None, required=False):
    for component in path:
        d = d.get(component)
        if d is None:
            break

    if type_ == bool and isinstance(d, str):
        if d.lower() not in ('true', 'false'):
            raise ValueError()
        d = 'true' == d.lower()
    elif type_ is not None and not isinstance(d, type_):
        # wrong type
        d = None

    if d is None and required:
        raise KeyError(f'path: {path} doesn\'t exist in given plist object')

    return d
