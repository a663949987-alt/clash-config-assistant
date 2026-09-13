$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$taskStream=New-Object IO.MemoryStream
$taskWriter=New-Object IO.BinaryWriter($taskStream)
$taskImages=@()
foreach($taskSize in @(16,24,32,48,64,128,256)) {
 $taskBitmap=New-Object Drawing.Bitmap($taskSize,$taskSize)
 $taskGraphics=[Drawing.Graphics]::FromImage($taskBitmap)
 $taskGraphics.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
 $taskGraphics.ScaleTransform($taskSize/256.0,$taskSize/256.0)
 $taskGraphics.Clear([Drawing.Color]::Transparent)
 $taskShape=New-Object Drawing.Drawing2D.GraphicsPath
 $taskShape.AddPolygon([Drawing.PointF[]]@([Drawing.PointF]::new(128,12),[Drawing.PointF]::new(232,50),[Drawing.PointF]::new(219,157),[Drawing.PointF]::new(186,207),[Drawing.PointF]::new(128,244),[Drawing.PointF]::new(70,207),[Drawing.PointF]::new(37,157),[Drawing.PointF]::new(24,50)))
 $taskBrush=New-Object Drawing.Drawing2D.LinearGradientBrush([Drawing.Point]::new(24,12),[Drawing.Point]::new(230,244),[Drawing.Color]::FromArgb(43,121,238),[Drawing.Color]::FromArgb(19,55,130))
 $taskGraphics.FillPath($taskBrush,$taskShape)
 $taskPen=New-Object Drawing.Pen([Drawing.Color]::White,14)
 $taskPen.StartCap=$taskPen.EndCap=[Drawing.Drawing2D.LineCap]::Round
 $taskGraphics.DrawLines($taskPen,[Drawing.PointF[]]@([Drawing.PointF]::new(79,145),[Drawing.PointF]::new(128,145),[Drawing.PointF]::new(128,90),[Drawing.PointF]::new(180,90)))
 $taskGraphics.FillEllipse([Drawing.Brushes]::White,59,125,40,40)
 $taskAccent=New-Object Drawing.SolidBrush([Drawing.Color]::FromArgb(94,239,211))
 $taskGraphics.FillEllipse($taskAccent,159,69,42,42)
 $taskPng=New-Object IO.MemoryStream
 $taskBitmap.Save($taskPng,[Drawing.Imaging.ImageFormat]::Png)
 $taskImages+=,@{Size=$taskSize;Bytes=$taskPng.ToArray()}
 $taskPng.Dispose();$taskAccent.Dispose();$taskPen.Dispose();$taskBrush.Dispose();$taskShape.Dispose();$taskGraphics.Dispose();$taskBitmap.Dispose()
}
$taskWriter.Write([uint16]0);$taskWriter.Write([uint16]1);$taskWriter.Write([uint16]$taskImages.Count)
$taskOffset=6+16*$taskImages.Count
foreach($taskImage in $taskImages){$taskDimension=if($taskImage.Size -eq 256){0}else{$taskImage.Size};$taskWriter.Write([byte]$taskDimension);$taskWriter.Write([byte]$taskDimension);$taskWriter.Write([byte]0);$taskWriter.Write([byte]0);$taskWriter.Write([uint16]1);$taskWriter.Write([uint16]32);$taskWriter.Write([uint32]$taskImage.Bytes.Length);$taskWriter.Write([uint32]$taskOffset);$taskOffset+=$taskImage.Bytes.Length}
foreach($taskImage in $taskImages){$taskWriter.Write([byte[]]$taskImage.Bytes)}
[IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'app.ico'),$taskStream.ToArray())
$taskWriter.Dispose();$taskStream.Dispose()
