import ctypes as ct


class ShadowEntry:
    """Shadow file entry format"""
    def __init__(self, line):
        self.entry = self._parse_line(line)

    def _parse_line(self, line):
        """Parse a line from the shadow file"""
        entry = {}
        fields = line.split(":")
        if len(fields) != 9:
            raise ValueError("Invalid shadow entry format")
        entry["user"] = fields[0]
        entry["passwd"] = self._parse_passwd(fields[1])
        entry["last_change"] = int(fields[2])
        entry["min_age"] = int(fields[3])
        entry["max_age"] = int(fields[4])
        entry["warn_period"] = int(fields[5])
        entry["inactive_period"] = int(fields[6])
        entry["expiration_date"] = int(fields[7])
        entry["reserved"] = fields[8]
        return entry

    def _parse_passwd(self, p_str):
        """Parse the password field
        Format: $id$[salt]$[hash]
        """
        pdict = {}
        p_fields = p_str.split("$")
        if len(p_fields) != 3:
            if p_str == "":
                return {"algo": "", "salt": "", "hash": ""}
            elif p_str == "*":
                return {"algo": "locked", "salt": "", "hash": ""}
            elif p_str in ["!", "!!"]:
                return {"algo": "disabled", "salt": "", "hash": ""}
        algo_id = p_fields[0]
        if algo_id == "1":
            pdict["algo"] = "md5"
        elif algo_id in ["2a", "2y"]:
            pdict["algo"] = "blowfish"
        elif algo_id == "5":
            pdict["algo"] = "sha256"
        elif algo_id == "6":
            pdict["algo"] = "sha512"
        elif algo_id == "y":
            pdict["algo"] = "yescrypt"
        else:
            raise ValueError("Unknown algorithm ID")    
        pdict["salt"] = p_fields[1]
        pdict["hash"] = p_fields[2]
        return pdict

class ShadowFile:

    def __init__(self, filename):
        self.filename = filename
        lines = {}