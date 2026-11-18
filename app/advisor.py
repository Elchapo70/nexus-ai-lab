"""Rule-based security advisor; no external AI service or secrets required."""
from fastapi import HTTPException
from pydantic import BaseModel, Field

ADVICE = {
    "PRIVATE_KEY": ("Clave privada expuesta", "Una clave privada dentro del código puede permitir acceso no autorizado.", "Revoca o rota la clave, elimínala del repositorio y de su historial cuando corresponda; usa un gestor de secretos."),
    "AWS_KEY": ("Posible clave de AWS", "Este patrón se parece a una clave de acceso AWS; verifica si es válida antes de concluir que existe una exposición.", "Desactiva la credencial si está activa y usa roles IAM o un gestor de secretos."),
    "HARDCODED_SECRET": ("Posible secreto incrustado", "Un valor sensible escrito directamente en código puede terminar en registros o repositorios públicos.", "Mueve el secreto a un gestor de secretos o variables de entorno y rota el valor expuesto."),
    "DEBUG_TRUE": ("Modo de depuración activado", "La depuración en producción puede revelar detalles internos según el framework.", "Desactiva DEBUG en producción y configura errores seguros."),
    "EVAL": ("Uso de eval()", "eval puede ejecutar expresiones arbitrarias cuando recibe datos no confiables.", "Reemplaza eval por un parser específico o validación estricta; no pases entradas de usuarios a eval."),
}

class ExplainRequest(BaseModel):
    rule: str = Field(min_length=1, max_length=80)

def explain(rule: str):
    if rule not in ADVICE:
        raise HTTPException(404, "Regla desconocida")
    title, reason, fix = ADVICE[rule]
    return {"rule": rule, "title": title, "explanation": reason, "recommendation": fix, "method": "rule-based", "disclaimer": "Orientación automática; requiere revisión humana."}
