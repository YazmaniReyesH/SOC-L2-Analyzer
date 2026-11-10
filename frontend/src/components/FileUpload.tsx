import { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { UploadCloud, FileSpreadsheet, Loader2, AlertCircle } from "lucide-react";

export function FileUpload({
  onFile,
  cargando,
  error,
}: {
  onFile: (file: File) => void;
  cargando: boolean;
  error: string | null;
}) {
  const [nombre, setNombre] = useState<string | null>(null);

  const onDrop = useCallback(
    (aceptados: File[]) => {
      if (aceptados.length > 0) {
        setNombre(aceptados[0].name);
        onFile(aceptados[0]);
      }
    },
    [onFile]
  );

  const { getRootProps, getInputProps, isDragActive, fileRejections } =
    useDropzone({
      onDrop,
      multiple: false,
      disabled: cargando,
      accept: {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
          ".xlsx",
        ],
        "application/vnd.ms-excel.sheet.macroEnabled.12": [".xlsm"],
      },
    });

  const rechazo = fileRejections.length > 0;

  return (
    <div className="mx-auto max-w-2xl">
      <div
        {...getRootProps()}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-10 text-center transition
          ${
            isDragActive
              ? "border-primary bg-primary/5"
              : "border-border bg-card hover:border-primary/60"
          }
          ${cargando ? "pointer-events-none opacity-70" : ""}`}
      >
        <input {...getInputProps()} />
        {cargando ? (
          <>
            <Loader2 className="mb-4 h-12 w-12 animate-spin text-primary" />
            <p className="text-lg font-medium">Analizando {nombre}…</p>
            <p className="text-sm text-muted-foreground">
              Parseando logs y ejecutando el motor de detección determinista.
            </p>
          </>
        ) : (
          <>
            <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary">
              <UploadCloud className="h-8 w-8" />
            </div>
            <p className="text-lg font-medium">
              {isDragActive
                ? "Suelta el archivo aquí"
                : "Arrastra el export del SIEM (.xlsx)"}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              o haz clic para seleccionarlo. Hoja esperada:{" "}
              <code className="rounded bg-muted px-1">SIEM Export</code>
            </p>
            {nombre && !error && (
              <div className="mt-4 flex items-center gap-2 text-sm text-muted-foreground">
                <FileSpreadsheet className="h-4 w-4" /> {nombre}
              </div>
            )}
          </>
        )}
      </div>

      {rechazo && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-critico/30 bg-critico/10 p-3 text-sm text-critico">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>Formato no válido. Sube un archivo .xlsx exportado del SIEM.</span>
        </div>
      )}

      {error && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-critico/30 bg-critico/10 p-3 text-sm text-critico">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
