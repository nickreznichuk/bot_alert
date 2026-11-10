// Draws the BotAlert app icon (a shield with a keyhole on a dark squircle) and writes Resources/AppIcon.icns.
// Run: swift tools/icon/make_icon.swift   (only needed after changing the design; the .icns is committed)
import AppKit

let root = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: a)
}

/// Shield outline in the 1024-point design space (y up).
func shieldPath(inset d: CGFloat = 0) -> NSBezierPath {
    let p = NSBezierPath()
    let left = NSPoint(x: 278 + d, y: 712 - d * 0.4), right = NSPoint(x: 746 - d, y: 712 - d * 0.4)
    let top = NSPoint(x: 512, y: 806 - d), bottom = NSPoint(x: 512, y: 196 + d * 1.25)
    p.move(to: top)
    p.curve(to: right, controlPoint1: NSPoint(x: 590, y: 772 - d), controlPoint2: NSPoint(x: 676, y: 728 - d * 0.6))
    p.curve(to: bottom, controlPoint1: NSPoint(x: 752 - d, y: 440), controlPoint2: NSPoint(x: 660 - d * 0.6, y: 268 + d))
    p.curve(to: left, controlPoint1: NSPoint(x: 364 + d * 0.6, y: 268 + d), controlPoint2: NSPoint(x: 272 + d, y: 440))
    p.curve(to: top, controlPoint1: NSPoint(x: 348, y: 728 - d * 0.6), controlPoint2: NSPoint(x: 434, y: 772 - d))
    p.close()
    return p
}

/// One continuous outline (a round head flowing into a tapered stem), so there is no seam where they meet.
func keyholePath() -> NSBezierPath {
    let head = NSPoint(x: 512, y: 566), r: CGFloat = 66, neck: CGFloat = 30
    let a = asin(neck / r) * 180 / .pi // angle between the neck edge and the vertical
    let p = NSBezierPath()
    p.appendArc(withCenter: head, radius: r, startAngle: -90 + a, endAngle: 270 - a, clockwise: false)
    p.line(to: NSPoint(x: 512 - 52, y: 372))
    p.appendArc(withCenter: NSPoint(x: 512, y: 372), radius: 52, startAngle: 180, endAngle: 360, clockwise: false)
    p.close()
    return p
}

func drawIcon() {
    let ctx = NSGraphicsContext.current!.cgContext

    // Body: dark navy squircle on Apple's 824-point grid, with a soft drop shadow.
    let body = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185)
    ctx.saveGState()
    let shadow = NSShadow()
    shadow.shadowColor = rgb(0, 0, 0, 0.35); shadow.shadowOffset = NSSize(width: 0, height: -10); shadow.shadowBlurRadius = 28
    shadow.set()
    rgb(14, 20, 46).setFill(); body.fill()
    ctx.restoreGState()

    ctx.saveGState()
    body.addClip()
    NSGradient(colors: [rgb(38, 52, 104), rgb(16, 22, 52), rgb(8, 11, 28)], atLocations: [0, 0.55, 1],
               colorSpace: .sRGB)!.draw(in: body, angle: -90)
    // Glow behind the shield.
    NSGradient(colors: [rgb(56, 200, 255, 0.38), rgb(56, 200, 255, 0)])!
        .draw(fromCenter: NSPoint(x: 512, y: 500), radius: 0, toCenter: NSPoint(x: 512, y: 500), radius: 430, options: [])
    // Radar rings.
    for (i, r) in [250.0, 340, 430, 520].enumerated() {
        let ring = NSBezierPath(ovalIn: NSRect(x: 512 - r, y: 500 - r, width: r * 2, height: r * 2))
        ring.lineWidth = 5
        rgb(120, 210, 255, 0.10 - CGFloat(i) * 0.02).setStroke(); ring.stroke()
    }
    // Top sheen.
    NSGradient(colors: [rgb(255, 255, 255, 0.10), rgb(255, 255, 255, 0)])!
        .draw(in: NSRect(x: 100, y: 640, width: 824, height: 284), angle: -90)
    ctx.restoreGState()

    // Shield with a cyan-to-blue gradient, its own shadow, and a light rim.
    let shield = shieldPath()
    ctx.saveGState()
    let s2 = NSShadow()
    s2.shadowColor = rgb(0, 10, 40, 0.55); s2.shadowOffset = NSSize(width: 0, height: -14); s2.shadowBlurRadius = 30
    s2.set()
    rgb(30, 140, 240).setFill(); shield.fill()
    ctx.restoreGState()
    NSGradient(colors: [rgb(110, 236, 255), rgb(44, 168, 250), rgb(30, 92, 220)], atLocations: [0, 0.5, 1],
               colorSpace: .sRGB)!.draw(in: shield, angle: -90)
    // Inner bevel: a slightly darker inset shield, then a highlight on its upper half.
    let inner = shieldPath(inset: 34)
    NSGradient(colors: [rgb(70, 206, 255), rgb(22, 116, 232)])!.draw(in: inner, angle: -90)
    ctx.saveGState()
    inner.addClip()
    NSGradient(colors: [rgb(255, 255, 255, 0.28), rgb(255, 255, 255, 0)])!
        .draw(in: NSRect(x: 240, y: 560, width: 544, height: 260), angle: -90)
    ctx.restoreGState()
    shield.lineWidth = 6
    rgb(255, 255, 255, 0.35).setStroke(); shield.stroke()

    // Keyhole cut into the shield.
    let hole = keyholePath()
    ctx.saveGState()
    let s3 = NSShadow()
    s3.shadowColor = rgb(255, 255, 255, 0.45); s3.shadowOffset = NSSize(width: 0, height: -4); s3.shadowBlurRadius = 2
    s3.set()
    rgb(10, 18, 44).setFill(); hole.fill()
    ctx.restoreGState()
    NSGradient(colors: [rgb(6, 12, 32), rgb(20, 34, 78)])!.draw(in: hole, angle: -90)
}

func png(size px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current!.imageInterpolation = .high
    let scale = CGFloat(px) / 1024
    NSGraphicsContext.current!.cgContext.scaleBy(x: scale, y: scale)
    drawIcon()
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("AppIcon-\(getpid()).iconset")
try? FileManager.default.removeItem(at: iconset)
try! FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try! png(size: base).write(to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
    try! png(size: base * 2).write(to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
let resources = root.appendingPathComponent("Resources")
try! FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
try! png(size: 512).write(to: resources.appendingPathComponent("AppIcon.png")) // README preview

let task = Process()
task.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
task.arguments = ["-c", "icns", iconset.path, "-o", resources.appendingPathComponent("AppIcon.icns").path]
try! task.run(); task.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
print(task.terminationStatus == 0 ? "Wrote Resources/AppIcon.icns and Resources/AppIcon.png" : "iconutil failed")
exit(task.terminationStatus)
