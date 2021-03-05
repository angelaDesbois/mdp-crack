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
    def hashCrack(md5, file, order, doneQueue):
        """
        Casse un Hash MD5 via une liste de mots-clé (file)
        :param md5: hash md5 à casser
        :param file: fichier de mdp à utiliser
        :return:
        """
        try:
            trouve = False
            ofile = open(file, "r")
            if Order.ASCEND == order:
                contain = reversed(list(ofile.readlines()))
            else:
                contain = ofile.readlines()
            for mot in contain:
                mot = mot.strip("\n")
                hashMd5 = hashlib.md5(mot.encode("utf8")).hexdigest()
                if hashMd5 == md5:
                    print(Couleur.VERT + "[+] Password Found : " + str(mot) + " (" + hashMd5 + ")" + Couleur.FIN)
                    trouve = True
                    doneQueue.put("Found")
                    break
            if not trouve:
                print(Couleur.ROUGE + "[-] Password Not Found " + Couleur.FIN)
                doneQueue.put("Not Found")
            ofile.close()
        except FileNotFoundError:
            print(Couleur.ROUGE + "[-] Error : no directory or file !" + Couleur.FIN)
            sys.exit(1)
        except Exception as err:
            print(Couleur.ROUGE + "error " + str(err) + Couleur.FIN)
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
            userAgent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:86.0) Gecko/20100101 Firefox/86.0"
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


    @staticmethod
    def work(workQueue, doneQueue, md5, file, order):
        """

        :param workQueue:
        :param doneQueue:
        :param md5:
        :param file:
        :param order:
        :return:
        """
        obj = workQueue.get()
        obj.hashCrack(md5, file, order, doneQueue)


    @staticmethod
    def smartCrack(md5, pattern, _index=0):
        """

        :param md5:
        :param pattern:
        :param _index:
        :return:
        """
        MAJ = string.ascii_uppercase  # ^
        NUMBER = string.digits        # ²   (^2)
        MIN = string.ascii_lowercase  # *

        if _index < len(pattern):
            if pattern[_index] in MAJ + NUMBER + MIN:
                Cracker.smartCrack(md5, pattern, _index + 1)
            if "^" == pattern[_index]:
                for c in MAJ:
                    p = pattern.replace("^", c, 1)
                    currentHash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currentHash == md5:
                        print(Couleur.VERT + "[+] PASSWORD FOUND " + p + Couleur.FIN)
                        sys.exit(0)
                    print("MAJ : " + p + " (" + currentHash + " )")
                    Cracker.smartCrack(md5, p, _index + 1)

            if "*" == pattern[_index]:
                for c in MIN:
                    p = pattern.replace("*", c, 1)
                    currentHash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currentHash == md5:
                        print(Couleur.VERT + "[+] PASSWORD FOUND " + p + Couleur.FIN)
                        sys.exit(0)
                    print("MIN : " + p + " (" + currentHash + " )")
                    Cracker.smartCrack(md5, p, _index + 1)

            if "²" == pattern[_index]:
                for c in NUMBER:
                    p = pattern.replace("²", c, 1)
                    currentHash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currentHash == md5:
                        print(Couleur.VERT + "[+] PASSWORD FOUND " + p + Couleur.FIN)
                        sys.exit(0)
                    print("NUMBER : " + p + " (" + currentHash + " )")
                    Cracker.smartCrack(md5, p, _index + 1)

        else:
            return


