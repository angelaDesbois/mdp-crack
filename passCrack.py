#!/usr/bin/env/ python3

# generateur md5
# crackeur mdp dico
# crackeur mdp recursive (printable: str = digits + ascii_letters + punctuation + whitespace)
# commands line args à la fin
import time
import string
import hashlib
import sys
import argparse
import atexit

parser = argparse.ArgumentParser(description="Password Cracker")
parser.add_argument("-f", "--file", dest="file", help="Path of the dictionnary file", required=False)
parser.add_argument("-g", "--gen", dest="gen", help="Generate MD5 hash of password", required=False)
parser.add_argument("-md5", "--md5", dest="md5", help="Hash password (MD5)", required=False)
parser.add_argument("-l", "--length", dest="plength", help="password length", required=False, type=int)

args = parser.parse_args()


def hashCrack(md5, file):
    try:
        trouve = False
        ofile = open(file, "r")
        for mot in ofile.readlines():
            mot = mot.strip("\n")
            hashMd5 = hashlib.md5(mot.encode("utf8")).hexdigest()
            if hashMd5 == md5:
                print("Mot de passe trouvé : " + str(mot) + " (" + hashMd5 + ")")
                trouve = True
        if not trouve:
            print("Mot de passe non trouvé ")
        ofile.close()
    except FileNotFoundError:
        print("Erreur : nom de dossier ou fichier introuvable!")
        sys.exit(1)
    except Exception as err :
        print("erreur " + str(err))
        sys.exit(2)




def crackIncremental(md5,length,currentPass = []):
    lettres = string.printable
    if length >= 1:
        if len(currentPass) == 0:
            currentPass = ['a' for _ in range(length)]
            crackIncremental(md5, length, currentPass)
        else:
            for c in lettres:
                currentPass[length - 1] = c
                print("Trying : " + "".join(currentPass))
                if hashlib.md5("".join(currentPass).encode("utf8")).hexdigest() == md5:
                    print("Password Found ! " + "".join(currentPass))
                    sys.exit(0)
                else:
                    crackIncremental(md5, length - 1, currentPass)


def displayName():
    print("Durée : " + str(time.time() - debut) + " secondes")



debut = time.time()
atexit.register(displayName)
if args.md5:
    print("Cracking Hash " + args.md5 )
    if args.file and not args.plength:
        print("Using Dictionnary File " + args.file)
        hashCrack(args.md5, args.file)
    elif args.plength and not args.file:
        print("Using incremental mode for " + str(args.plength) + "letters")
        crackIncremental(args.md5, args.plength)
    else:
        print("Please choose either -f or -l argument")
else:
    print("MD5 Hash not provided")
if args.gen:
    print("MD5 Hash of " + args.gen + ": " + hashlib.md5(args.gen.encode("utf8")).hexdigest())


print("Durée : " + str(time.time() - debut) + " secondes")

 # python passCrack.py -g test
 # python passCrack.py -f liste_francais.txt -md5 098f6bcd4621d373cade4e832627b4f6
 # python passCrack.py -l 4 -md5 098f6bcd4621d373cade4e832627b4f6