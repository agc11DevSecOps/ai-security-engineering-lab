import ast


def parse_value(record_id: str):
    return ast.literal_eval(record_id)
