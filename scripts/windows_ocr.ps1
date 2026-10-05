param(
    [Parameter(Mandatory = $true, ParameterSetName = "File")]
    [string]$ImagePath,

    [Parameter(Mandatory = $true, ParameterSetName = "Directory")]
    [string]$DirectoryPath
)

# This fixed helper exposes the Windows Runtime OCR engine to the local Python
# development server. Python validates that every path is inside its artifact
# directory before invoking this script; this script never evaluates input as code.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object {
        $_.Name -eq "AsTask" -and
        $_.IsGenericMethod -and
        $_.GetParameters().Count -eq 1
    } |
    Select-Object -First 1

if ($null -eq $asTask) {
    throw "Windows Runtime task support is unavailable"
}

function Wait-WindowsRuntimeOperation {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Operation,

        [Parameter(Mandatory = $true)]
        [Type]$ResultType
    )

    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    $task.Wait()
    return $task.Result
}

$allowedExtensions = @(".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff")
if ($PSCmdlet.ParameterSetName -eq "File") {
    $resolvedFile = (Resolve-Path -LiteralPath $ImagePath -ErrorAction Stop).Path
    $files = @([IO.FileInfo]::new($resolvedFile))
}
else {
    $resolvedDirectory = (Resolve-Path -LiteralPath $DirectoryPath -ErrorAction Stop).Path
    $files = @(
        Get-ChildItem -LiteralPath $resolvedDirectory -File -ErrorAction Stop |
            Where-Object { $allowedExtensions -contains $_.Extension.ToLowerInvariant() } |
            Sort-Object -Property FullName
    )
}

if ($files.Count -eq 0) {
    throw "No supported images were supplied for OCR"
}

$storageFileType = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$randomAccessStreamType = [Windows.Storage.Streams.IRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
$bitmapDecoderType = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$softwareBitmapType = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$ocrEngineType = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
$ocrResultType = [Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType = WindowsRuntime]
$engine = $ocrEngineType::TryCreateFromUserProfileLanguages()

if ($null -eq $engine) {
    throw "No compatible Windows OCR language is installed"
}

$items = foreach ($fileInfo in $files) {
    if ($allowedExtensions -notcontains $fileInfo.Extension.ToLowerInvariant()) {
        continue
    }

    $stream = $null
    $bitmap = $null
    try {
        $storageFile = Wait-WindowsRuntimeOperation `
            ($storageFileType::GetFileFromPathAsync($fileInfo.FullName)) `
            $storageFileType
        $stream = Wait-WindowsRuntimeOperation `
            ($storageFile.OpenAsync([Windows.Storage.FileAccessMode]::Read)) `
            $randomAccessStreamType
        $decoder = Wait-WindowsRuntimeOperation `
            ($bitmapDecoderType::CreateAsync($stream)) `
            $bitmapDecoderType
        $bitmap = Wait-WindowsRuntimeOperation `
            ($decoder.GetSoftwareBitmapAsync()) `
            $softwareBitmapType
        $ocrResult = Wait-WindowsRuntimeOperation `
            ($engine.RecognizeAsync($bitmap)) `
            $ocrResultType

        [ordered]@{
            path = $fileInfo.FullName
            text = $ocrResult.Text
            language = $engine.RecognizerLanguage.LanguageTag
            width = $bitmap.PixelWidth
            height = $bitmap.PixelHeight
        }
    }
    catch {
        [ordered]@{
            path = $fileInfo.FullName
            error = $_.Exception.GetType().Name
        }
    }
    finally {
        if ($null -ne $bitmap) {
            $bitmap.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
