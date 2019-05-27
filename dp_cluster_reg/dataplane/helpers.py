class Dependency:
    def __init__(self, service_name, display_name):
        self.service_name = service_name
        self.display_name = display_name

    def __eq__(self, that): return isinstance(that, type(
        self)) and self.service_name == that.service_name

    def __hash__(self): return hash(self.service_name)


class Tag:
    @classmethod
    def random(self, name): return self("%s-%s" % (name, time.time()))
    def __init__(self, name): self.name = name
    def __str__(self): return self.name
