

def parse(c, src, dst, proto):
    truncated = False
    content=[]
    if c[0].startswith('[truncated]'):
        method, url = c[0].replace('[truncated] ', '').split(' ')
        version = None
    else:
        method, url, version = c[0].split(' ')

    for ln,line in enumerate(c[1:]):
        if not len(line.strip()):
            continue
        if line.find('[truncated]') > -1:
            truncated = True

        if line.startswith('Credentials: '):
            content.append(('HTTP_AUTH', line[12:]))

        if line.startswith('Line-based text data:'):
            content.append(('HTTP_POST_DATA', c[ln+2]))

    if len(content):
        content.append(('URL:', url))
        content.append(('TRUNCATED:', str(truncated)))
    return content


