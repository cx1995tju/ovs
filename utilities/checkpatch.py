line_length_blacklist = ['.am', '.at', 'etc', '.in', '.m4', '.mk', '.patch',
                         '.py']
leading_whitespace_blacklist = ['.mk', '.am', '.at']
     lambda x: not any([fmt in x for fmt in line_length_blacklist]),
     lambda x: not any([fmt in x for fmt in leading_whitespace_blacklist]),
    return lambda x: regex.search(x) is not None
    [re.escape(op) for op in ['/', '%', '<<', '>>', '<=', '>=', '==', '!=',
       '[^" +(]\+[^"+;]', '[^" -(]-[^"->;]', '[^" <>=!^|+\-*/%&]=[^"=]']
            parse = 2
        if parse == 1:
                parse = parse + 1
        elif parse == 0:
                parse = parse + 1
        elif parse == 2:
        optlist, args = getopt.getopt(args, 'bhlstf',
                                       "skip-trailing-whitespace"])