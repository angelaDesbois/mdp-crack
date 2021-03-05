#!/usr/bin/env/ python3
# coding:utf-8

"""
todo : a faire en C pr + efficace
generateur md5
crackeur mdp dico
crackeur mdp recursive (printable: str = digits + ascii_letters + punctuation + whitespace)
carckeur mdp en ligne
crackeur regex style
commands line args à la fin
"""

import time
import argparse
import atexit
from cracker import *
import multiprocessing

def displayTime():
    print("Durée : " + str(time.time() - debut) + " secondes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-f", "--file", dest="file", help="Path of the dictionnary file", required=False)
    parser.add_argument("-g", "--gen", dest="gen", help="Generate MD5 hash of password", required=False)
    parser.add_argument("-md5", "--md5", dest="md5", help="Hash password (MD5)", required=False)
    parser.add_argument("-l", "--length", dest="plength", help="password length", required=False, type=int)
    parser.add_argument("-w", "--online", dest="online", help="look for hash online", required=False, action="store_true")
    parser.add_argument("-p", "--pattern", dest="pattern", help="Use password pattern (^=MAJ, *=MIN, ²=NUMBER)")

    args = parser.parse_args()

    processes = []
    workQueue = multiprocessing.Queue()
    doneQueue = multiprocessing.Queue()
    cracker = Cracker()

    debut = time.time()
    atexit.register(displayTime)

    if args.gen:
        print("[*] Hash MD5 of " + args.gen + " = " + hashlib.md5(args.gen.encode("utf8")).hexdigest())

    if args.md5:
        print("[*] Cracking Hash " + args.md5)
        if args.file and not args.plength:
            print("[*] Using Dictionnary File " + args.file)
            #False = processus descendant , True = processus ascendant
            p1 = multiprocessing.Process(target=Cracker.work, args=(workQueue, doneQueue, args.md5, args.file, False))
            workQueue.put(cracker)
            p1.start()
            p2 = multiprocessing.Process(target=Cracker.work, args=(workQueue, doneQueue, args.md5, args.file, True))
            workQueue.put(cracker)
            p2.start()

            while True:
                data = doneQueue.get()
                if data == "Found" or data == "Not Found":
                    p1.kill()
                    p2.kill()
                    break


           # Cracker.hashCrack(args.md5, args.file)
        elif args.plength and not args.file:
            print("[*] Using incremental mode for " + str(args.plength) + "letters")
            Cracker.crackIncremental(args.md5, args.plength)
        elif args.online:
            print("[*] Using online mode")
            Cracker.crackOnline(args.md5)
        elif args.pattern:
            print("[*] Using password pattern" + args.pattern)
            Cracker.smartCrack(args.md5, args.pattern)
        else:
            print(Couleur.ROUGE + "[-] Please choose either -f or -l argument with -md5" + Couleur.FIN)
    else:
        print(Couleur.ROUGE + "[-] MD5 Hash not provided" + Couleur.FIN)

# ex:
 # python passCrack.py -g test
 # python passCrack.py -f liste_francais.txt -md5 098f6bcd4621d373cade4e832627b4f6
 # python passCrack.py -l 4 -md5 098f6bcd4621d373cade4e832627b4f6
 # python passCrack.py -md5 e10adc3949ba59abbe56e057f20f883e -w
 #python passCrack.py -md5 91a9355bbeb0370335f511652bf6f2cc -p ^**²  (pr mdp longueur 4)
 #python passCrack.py -md5 b410e85fb1c55ccd1e52beb745fc3e19 -p K****67