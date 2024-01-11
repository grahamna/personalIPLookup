import ipLookup
import random

class TicketObj:
    def __init__(self):
        self.data = {}

    def __getitem__(self, varName):
        return self.data[varName]

    def __setitem__(self, varName, num):
        self.data[varName] = self.data.get(varName, 0) + num

    def __delitem__(self, varName):
        del self.data[varName]

    def __str__(self):
        if not self.data:
            # marking data for deletion
            return 'DELETE_ME'
        
        elif len(self.data) == 1:
            # case for single param
            varName, num = next(iter(self.data.items()))
            return varName if num == 1 else f'({num}) {varName}'
        
        else:
            # case for multiple params within dict
            return '\n\t\t' + '\n\t\t'.join(f'({num}) {varName}' for varName, num in self.data.items())
        
class IpTicketObj(TicketObj):
    def __init__(self):
        super().__init__()
    
    def __str__(self):
        if not self.data:
            # marking data for deletion
            return 'DELETE_ME'
        
        elif len(self.data) == 1: 
            # case for single param
            varName, num = next(iter(self.data.items()))
            rand = random.randint(0,7)
            ipOut = ipLookup.processIp(varName, rand, True)
            if ipOut is not None:
                return f'{varName} - {ipOut}' if num == 1 else f'({num}) {varName} - {ipOut}'
            else:
                return varName if num == 1 else f'({num}) {varName}'
            
        else: 
            # case for multiple params within dict
            res = ''
            for varName, num in self.data.items():
                rand = random.randint(0,7)
                ipOut = ipLookup.processIp(None, varName, rand, True)
                if ipOut is not None:
                    res = res + (f"\n\t\t({num}) {varName} - {ipOut}")
                else:
                    res = res + (f"\n\t\t({num}) {varName}")
            return res