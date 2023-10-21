class TicketObj:
    def __init__(self):
        self.data = {}

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        if key in self.data:
            self.data[key] += value
        else:
            self.data[key] = value

    def __delitem__(self, key):
        del self.data[key]

    def __str__(self):
        return str(self.data)
    
    def toString(self):
        if self.data.__len__()== 0:
            return 'DELETE_ME'
        elif self.data.__len__()== 1:
            varName, num = next(iter(self.data.items()))
            if num == 1:
                return varName
            else:
                return f'({num}) {varName}'
        else:
            return '\n\t'+'\n\t'.join(f'({num}) {varName}' for varName, num in self.data.items())