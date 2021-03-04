# coding:utf-8
import string
import hashlib
import sys
import urllib.request
import urllib.response
import urllib.error
from utils import *

class Cracker:
    @staticmethod
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
    @staticmethod
    def crackIncremental(md5,length,currentPass = []):
        lettres = string.printable
        if length >= 1:
            if len(currentPass) == 0:
                currentPass = ['a' for _ in range(length)]
                Cracker.crackIncremental(md5, length, currentPass)
            else:
                for c in lettres:
                    currentPass[length - 1] = c
                    print("[*] Trying : " + "".join(currentPass))
                    if hashlib.md5("".join(currentPass).encode("utf8")).hexdigest() == md5:
                        print(Couleur.VERT + "Password Found ! " + "".join(currentPass) + Couleur.FIN)
                        sys.exit(0)
                    else:
                        Cracker.crackIncremental(md5, length - 1, currentPass)


    @staticmethod
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