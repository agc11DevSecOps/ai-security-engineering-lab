package modeladmission

# Deniega por defecto si no se cumplen las condiciones de abajo
default allow := false

# object.get(objeto, clave, valor_por_defecto) -> nunca devuelve undefined,
# si la clave no existe devuelve el tercer argumento en su lugar.
scanned_value := object.get(input.metadata.annotations, "model.security/scanned", "missing")
signed_value := object.get(input.metadata.annotations, "model.security/signed", "missing")
format_value := object.get(input.metadata.annotations, "model.security/format", "missing")

allow if {
    scanned_value == "true"
    signed_value == "true"
    format_value == "safetensors"
}

deny_reasons contains "modelo no escaneado con ModelScan" if {
    scanned_value != "true"
}

deny_reasons contains "modelo no firmado con Cosign" if {
    signed_value != "true"
}

deny_reasons contains "formato inseguro (se requiere safetensors)" if {
    format_value != "safetensors"
}
