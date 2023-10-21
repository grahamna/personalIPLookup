class TicketObj:
    def __init__(self):
        self.data = {}

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = self.data.get(key, 0) + value

    def __delitem__(self, key):
        del self.data[key]

    def __str__(self):
        if not self.data:
            return 'DELETE_ME'
        elif len(self.data) == 1:
            varName, num = next(iter(self.data.items()))
            return varName if num == 1 else f'({num}) {varName}'
        else:
            return '\n\t' + '\n\t'.join(f'({num}) {varName}' for varName, num in self.data.items())