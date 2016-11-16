
def print_table(title, headers, rows):
    widths = []
    
    for i in xrange(len(headers)):
        z = map(len, [row[i] for row in rows])
        z.append(len(headers[i]))
        widths.append(max(z))
    
    width = sum(widths) + len(headers) + 1
    print "-"* width
    print "|" + title.center(width-2) + "|"
    print "-"* width
    hline = "|"
    for i in xrange(len(headers)):
        hline += headers[i].ljust(widths[i]) + "|"
    print hline

    print "-"* width
    for row in rows:
        line = "|"
        for i in xrange(len(row)):
            line += row[i].ljust(widths[i]) + "|"
        print line
    
    if len(rows) == 0:
        print "|" + "No entries".center(width-2) + "|"
    print "-"* width
    print ""
