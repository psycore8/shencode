import hashlib

class sha1:
    Author = 'psycore8'
    Description = 'SHA1 Checksum'
    Version = '1.0.0'

    def calculate_sha1(file_path):
        sha1 = hashlib.sha1()  # SHA-1 Hash-Objekt erstellen
        buffer_size = 65536    # 64KB große Blöcke

        # Datei im Binärmodus öffnen und blockweise lesen
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                sha1.update(chunk)  # Hash-Objekt mit jedem Block aktualisieren

        # Hash-Wert als Hex-String zurückgeben
        return sha1.hexdigest()

    # Beispiel für die Berechnung des SHA-1-Werts einer Datei
    #file_path = "meine_datei.txt"
    #sha1_hash = calculate_sha1(file_path)
    #print("SHA-1 Hash der Datei:", sha1_hash)
