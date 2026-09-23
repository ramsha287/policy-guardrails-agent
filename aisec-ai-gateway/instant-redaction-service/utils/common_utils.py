import string

def normalize(text):
    """
    Normalize text for comparison: strip whitespace, lowercase, and remove leading/trailing punctuation.
    """
    return text.strip().lower().strip(string.punctuation)


def normalize_input_for_presidio(text: str) -> str:
    lines = text.splitlines()
    cleaned_lines = [line.strip() for line in lines if line.strip()]
    return " \n ".join(cleaned_lines)
