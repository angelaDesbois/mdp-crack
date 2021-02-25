#!/usr/bin/env/ python3

# crackeur mdp dictionnaire av generateur md5
import random
import time
import string
import hashlib
import sys

motDePasse = input("Quel est le mot de passe : ")
motDePasseMd5 = hashlib.md5(motDePasse.encode("utf8")).hexdigest()
print(motDePasseMd5)


def hashCrack():
    try:
        mots_fr = open("liste_francais.txt", "r")
        trouve = False
        for mot in mots_fr.readlines():
            mot = mot.strip("\n").encode("utf8")
            hashMd5 = hashlib.md5(mot).hexdigest()
            if hashMd5 == motDePasseMd5:
                print("Mot de passe trouvé : " + str(mot) + " (" + hashMd5 + ")")
                trouve = True
        if not trouve:
            print("Mot de passe non trouvé ")
        mots_fr.close()
    except FileNotFoundError:
        print("Erreur : nom de dossier ou fichier introuvable!")
        sys.exit(1)
    except Exception as err :
        print("erreur " + str(err))
        sys.exit(2)


debut = time.time()
hashCrack()
print("Durée : " + str(time.time() - debut) + " secondes")