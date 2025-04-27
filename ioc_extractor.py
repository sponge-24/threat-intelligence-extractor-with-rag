from ioc_finder import find_iocs

def extract_iocs_from_pdf(markdown_text):
    iocs = find_iocs(markdown_text)
    exclude_keys = {"attack_mitigations", "attack_tactics", "attack_techniques", "email_addresses_complete"}
    filtered_iocs = {category: values for category, values in iocs.items() if category not in exclude_keys and values}
    return [{"IoCs": filtered_iocs}]
    