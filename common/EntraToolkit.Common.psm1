#Requires -Version 7.4

# One function per file under public/. Dot-sourcing at import time keeps the
# module source navigable (and diff-friendly) while still exposing a single,
# versioned module surface to the scripts that consume it.

$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'public') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in $public) {
    try {
        . $file.FullName
    }
    catch {
        # Fail loudly: a module that silently imports half its functions produces
        # "command not found" errors far away from the real cause.
        throw "Failed to import function file '$($file.FullName)': $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function $public.BaseName
