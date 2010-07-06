

def parse(a):
    truncated = False
    content=[]
    expertInfo=[]
    for l in a:
        if not len(l.strip()):
            continue
        if l.find('[truncated]') > -1:
            truncated = True
            tmp = l.replace('[truncated]', '')
        else:
            tmp = l

        if tmp.startswith('['):
            expertInfo.append(tmp)
        else:
            content.append(tmp)

    content.append('truncated: %s' % str(truncated))
    content.extend(expertInfo)
    return content
