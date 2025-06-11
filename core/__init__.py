class EvasionTechnique:
    """Base class for all evasion techniques."""
    def __init__(self, name, description, options):
        self.name = name
        self.description = description
        # Options are defined as a list of dictionaries for click integration
        # Each dict: {'name': '--option', 'type': str, 'required': True, 'help': '...'}
        self.options = options

    def generate(self, **kwargs):
        """The main method to generate the artifact. Must be implemented by subclasses."""
        raise NotImplementedError("The 'generate' method must be implemented by the technique class.")