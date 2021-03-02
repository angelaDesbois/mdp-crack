#!/usr/bin/env/ python3
# coding:utf-8

"""
generateur md5
crackeur mdp dico
crackeur mdp recursive (printable: str = digits + ascii_letters + punctuation + whitespace)
carckeur mdp en ligne
commands line args à la fin
"""

import time
import string
import hashlib
import sys
import argparse
import atexit
import urllib.request
import urllib.response
import urllib.error


class Couleur:
    ROUGE = '\033[91m'
    VERT = '\033[92m'
    ORANGE = '\033[93m'
    FIN = '\033[0m'



parser = argparse.ArgumentParser(description="Password Cracker")
parser.add_argument("-f", "--file", dest="file", help="Path of the dictionnary file", required=False)
parser.add_argument("-g", "--gen", dest="gen", help="Generate MD5 hash of password", required=False)
parser.add_argument("-md5", "--md5", dest="md5", help="Hash password (MD5)", required=False)
parser.add_argument("-l", "--length", dest="plength", help="password length", required=False, type=int)
parser.add_argument("-w", "--online", dest="online", help="look for hash online", required=False, action="store_true")

args = parser.parse_args()


def hashCrack(md5, file):
    """
    Casse un Hash MD5 via une liste de mots-clé (file)
    :param md5: hash md5 à casser
    :param file: fichier de mdp à utiliser
    :return:
    """
    try:
        trouve = False
        ofile = open(file, "r")
        for mot in ofile.readlines():
            mot = mot.strip("\n")
            hashMd5 = hashlib.md5(mot.encode("utf8")).hexdigest()
            if hashMd5 == md5:
                print(Couleur.VERT + "[+] Mot de passe trouvé : " + str(mot) + " (" + hashMd5 + ")" + Couleur.FIN)
                trouve = True
        if not trouve:
            print(Couleur.ROUGE + "[-] Mot de passe non trouvé " + Couleur.FIN)
        ofile.close()
    except FileNotFoundError:
        print(Couleur.ROUGE + "[-] Erreur : nom de dossier ou fichier introuvable!" + Couleur.FIN)
        sys.exit(1)
    except Exception as err :
        print(Couleur.ROUGE + "erreur " + str(err) + Couleur.FIN)
        sys.exit(2)



# casse un hash md5 via methode incrémentale pr un mdp de longueur length
def crackIncremental(md5,length,currentPass = []):
    lettres = string.printable
    if length >= 1:
        if len(currentPass) == 0:
            currentPass = ['a' for _ in range(length)]
            crackIncremental(md5, length, currentPass)
        else:
            for c in lettres:
                currentPass[length - 1] = c
                print("[*] Trying : " + "".join(currentPass))
                if hashlib.md5("".join(currentPass).encode("utf8")).hexdigest() == md5:
                    print(Couleur.VERT + "Password Found ! " + "".join(currentPass) + Couleur.FIN)
                    sys.exit(0)
                else:
                    crackIncremental(md5, length - 1, currentPass)

def crackOnline(md5):
    try:

        userAgent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; fr-FR; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7"
        headers = {'User-agent':userAgent}
        url = "https://www.google.fr/search?hl=fr&q=" + md5
        requete = urllib.request.Request(url, None, headers)
        reponse = urllib.request.urlopen(requete)
    except urllib.error.HTTPError as e:
        print("Erreur HTTP : " + e.code)
    except urllib.error.URLError as e:
        print("Erreur d'URL : " + e.reason)

    if "Aucun document " in str(reponse.read()):
        print(Couleur.ROUGE + "[-] HASH NOT FOUND WITH GOOGLE " + Couleur.FIN)
    else:
        print(Couleur.VERT + "[+] PASSWORD FOUND " + url + Couleur.FIN)



def displayName():
    print("Durée : " + str(time.time() - debut) + " secondes")



debut = time.time()
atexit.register(displayName)

if args.gen:
    print("[*] Hash MD5 of " + args.gen + " = " + hashlib.md5(args.gen.encode("utf8")).hexdigest())

if args.md5:
    print("[*] Cracking Hash " + args.md5 )
    if args.file and not args.plength:
        print("[*] Using Dictionnary File " + args.file)
        hashCrack(args.md5, args.file)
    elif args.plength and not args.file:
        print("[*] Using incremental mode for " + str(args.plength) + "letters")
        crackIncremental(args.md5, args.plength)
    elif args.online:
        print("[*] Using online mode")
        crackOnline(args.md5)


    else:
        print(Couleur.ROUGE + "[-] Please choose either -f or -l argument with -md5" + Couleur.FIN)
else:
    print(Couleur.ROUGE + "[-] MD5 Hash not provided" + Couleur.FIN)



print("Durée : " + str(time.time() - debut) + " secondes")

 # python passCrack.py -g test
 # python passCrack.py -f liste_francais.txt -md5 098f6bcd4621d373cade4e832627b4f6
 # python passCrack.py -l 4 -md5 098f6bcd4621d373cade4e832627b4f6
 # python passCrack.py -md5 e10adc3949ba59abbe56e057f20f883e -w