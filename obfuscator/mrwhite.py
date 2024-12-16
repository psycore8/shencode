import utils.arg

class ByteToChemicalMapping:
    Author = 'psycore8'
    Description = 'Obfuscate bytes - the Breaking Bad Style'
    Version = '1.0.0'

    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.mapping = {
        i: f"Chemical Compound {i}" for i in range(256)
    }
        
    def init():
        spName = 'bytes2chem'
        spArgList = [
            ['-i', '--input', '', '', 'Input File'],
            ['-o', '--output', '', '', 'Output File']
        ]
        utils.arg.CreateSubParser(spName, ByteToChemicalMapping.Description, spArgList)
        
    def byte_to_chemical(self, byte_sequence):
        """
        Konvertiert eine Sequenz von Bytes (0-255) in chemische Verbindungen.

        :param byte_sequence: Liste von Bytes (z. B. [0, 1, 2, 255])
        :return: Liste von Strings, die die chemischen Verbindungen repräsentieren
        """
        compounds = []
        for byte in byte_sequence:
            compound = self.mapping.get(byte, f"Unknown byte: {byte}")
            compounds.append(compound)
        return compounds