# @author: Ramy CHEMAK
# @university: INSA Centre Val de Loire et Université d'Orléans
# @laboratory: Laboratoire d'Informatique Fondamentale d'Orléans (LIFO-EA 4022)


def extract_record(file="record3.txt", col_s="frequency"):
    f = open(file, "r", encoding="utf8")
    coup = []
    cols = []
    rec = []
    for l in f.readlines():
        #print(f"> {l}")
        coup = l[:-1].split(' = ')
        if coup[0] == col_s:
            continue
        cols.append(coup[0])
        try:
            rec.append(int(coup[1]))
        except ValueError:
            rec.append(coup[1])
    #print(f"Columns ({len(cols)}) > {cols}")
    #print(f"Record ({len(rec)}) > {rec}")
    f.close()
    return [cols, rec]

#extract_record()

# ----- Experience 1 -----
# sex = 1

# ----- Experience 2 -----
# disp_type = 'OWNER'
# gender = 'Female'

# ----- Experience 3 -----
# status = 'C'
# frequency = 'POLATEK MESICNE'
# disp_type = 'OWNER'
# gender = 'Female'
