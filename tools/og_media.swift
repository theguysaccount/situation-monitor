// Renders The Situation Monitor's share assets with macOS's own frameworks (no downloads):
//   og-card.png (1200x630 title card), og-video.mp4 (8 s seamless loop), favicon.png, apple-touch-icon.png
// Usage (pick an SDK that matches your Swift compiler if the default does not): swiftc -O tools/og_media.swift -o /tmp/og_media && /tmp/og_media site
import AVFoundation
import CoreGraphics
import CoreText
import Foundation
import ImageIO
import UniformTypeIdentifiers

let W = 1200, H = 630, FPS = 30, SECONDS = 8.0
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."
let srgb = CGColorSpace(name: CGColorSpace.sRGB)!

func rgb(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: a)
}

let NAVY = rgb(0x0a2552), NAVY_DEEP = rgb(0x050d1f), INK = rgb(0xffffff), INK2 = rgb(0xb9c7e2)
let RED = rgb(0xd0242c), YELLOW = rgb(0xffc426), BLUE = rgb(0x3987e5), ORANGE = rgb(0xd95926), CYAN = rgb(0x6fd3ff)
let LV: [Int: CGColor] = [5: rgb(0x2f62c9), 4: rgb(0x16804a), 3: rgb(0xf2b705), 2: rgb(0xd0242c)]
let HEAVY = "AvenirNextCondensed-Heavy", BOLD = "AvenirNextCondensed-Bold", DEMI = "AvenirNextCondensed-DemiBold", MONO = "Menlo-Regular", MONOB = "Menlo-Bold"

/// Top-left coordinates on a Core Graphics context (whose origin is bottom-left).
struct Canvas {
    let ctx: CGContext
    let h: CGFloat
    func r(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ hh: CGFloat) -> CGRect { CGRect(x: x, y: h - y - hh, width: w, height: hh) }
    func fill(_ rect: CGRect, _ c: CGColor) { ctx.setFillColor(c); ctx.fill(rect) }
    func rounded(_ rect: CGRect, _ rad: CGFloat, fill: CGColor? = nil, stroke: CGColor? = nil, lw: CGFloat = 1) {
        let p = CGPath(roundedRect: rect, cornerWidth: rad, cornerHeight: rad, transform: nil)
        if let f = fill { ctx.addPath(p); ctx.setFillColor(f); ctx.fillPath() }
        if let s = stroke { ctx.addPath(p); ctx.setStrokeColor(s); ctx.setLineWidth(lw); ctx.strokePath() }
    }
    func line(_ text: String, _ font: String, _ size: CGFloat, _ color: CGColor, kern: CGFloat = 0) -> CTLine {
        let f = CTFontCreateWithName(font as CFString, size, nil)
        let attrs: [NSAttributedString.Key: Any] = [
            NSAttributedString.Key(kCTFontAttributeName as String): f,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): color,
            NSAttributedString.Key(kCTKernAttributeName as String): kern,
        ]
        return CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: attrs))
    }
    func width(_ l: CTLine) -> CGFloat { CGFloat(CTLineGetTypographicBounds(l, nil, nil, nil)) }
    @discardableResult
    func text(_ s: String, _ font: String, _ size: CGFloat, _ color: CGColor, x: CGFloat, baseline: CGFloat, kern: CGFloat = 0, align: Int = 0) -> CGFloat {
        let l = line(s, font, size, color, kern: kern)
        let w = width(l)
        ctx.textMatrix = .identity
        ctx.textPosition = CGPoint(x: align == 0 ? x : align == 1 ? x - w / 2 : x - w, y: h - baseline)
        CTLineDraw(l, ctx)
        return w
    }
    func radial(_ cx: CGFloat, _ cy: CGFloat, _ radius: CGFloat, _ c: CGColor) {
        let comps = c.components ?? [1, 1, 1, 1]
        let clear = CGColor(srgbRed: comps[0], green: comps[1], blue: comps[2], alpha: 0)
        let g = CGGradient(colorsSpace: srgb, colors: [c, clear] as CFArray, locations: [0, 1])!
        let p = CGPoint(x: cx, y: h - cy)
        ctx.drawRadialGradient(g, startCenter: p, startRadius: 0, endCenter: p, endRadius: radius, options: [])
    }
    func clip(_ rect: CGRect, _ body: () -> Void) { ctx.saveGState(); ctx.clip(to: rect); body(); ctx.restoreGState() }
}

// A small deterministic random source so every frame and render matches.
struct Rand { var s: UInt64; mutating func next() -> Double { s = s &* 6364136223846793005 &+ 1442695040888963407; return Double((s >> 33) % 10_000) / 10_000 } }

let CVES = ["CVE-2026-109618  PHP", "CVE-2026-109619  PHP", "CVE-2026-114625  ARISTA VCO", "CVE-2026-110447  COLLABORA",
            "CVE-2026-102764  BEYONDTRUST", "CVE-2025-61624   FORTINET", "CVE-2026-0257    PAN-OS", "CVE-2026-21589   ATLASSIAN",
            "CVE-2026-96656   PLEX", "CVE-2026-105134  AHSAY", "CVE-2026-106931  SITEGUARD", "CVE-2026-110936  SIEMENS"]
let GROUPS: [(String, CGFloat)] = [("qilin", 1.0), ("akira", 0.62), ("lockbit5", 0.48), ("safepay", 0.41), ("inc", 0.33)]

func screen(_ c: Canvas, _ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, glow: CGColor, _ body: (CGRect) -> Void) {
    c.radial(x + w / 2, y + h / 2, w * 0.95, glow)
    c.rounded(c.r(x - 5, y - 5, w + 10, h + 10), 7, fill: rgb(0x0b1222), stroke: rgb(0x22314e), lw: 2)
    let inner = c.r(x, y, w, h)
    c.rounded(inner, 3, fill: rgb(0x061231))
    c.clip(inner) {
        body(inner)
        for yy in stride(from: CGFloat(0), to: h, by: 3) { c.fill(c.r(x, y + yy, w, 1), rgb(0x000000, 0.18)) }
        c.radial(x + w * 0.3, y + h * 0.15, w * 0.8, rgb(0xffffff, 0.05))
    }
}

func drawScene(_ c: Canvas, t: Double) {
    let ctx = c.ctx
    ctx.setShouldAntialias(true)
    ctx.setAllowsFontSmoothing(true)
    // Room
    let bg = CGGradient(colorsSpace: srgb, colors: [rgb(0x0b1d40), NAVY_DEEP] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 0, y: c.h), end: CGPoint(x: 0, y: 0), options: [])
    c.radial(880, 250, 520, rgb(0x1b4290, 0.45))

    // The wall of screens
    let sw: CGFloat = 168, sh: CGFloat = 112, gx: CGFloat = 16, gy: CGFloat = 18, x0: CGFloat = 640, y0: CGFloat = 46
    func cell(_ col: Int, _ row: Int) -> (CGFloat, CGFloat) { (x0 + CGFloat(col) * (sw + gx), y0 + CGFloat(row) * (sh + gy)) }
    let blinkOn = t.truncatingRemainder(dividingBy: 1.0) < 0.62

    // 1. SITCON board escalating 5 -> 2, then holding
    let level = t < 0.7 ? 5 : t < 1.4 ? 4 : t < 2.1 ? 3 : 2
    var (sx, sy) = cell(0, 0)
    screen(c, sx, sy, sw, sh, glow: rgb(0xd0242c, level == 2 ? 0.30 : 0.12)) { _ in
        c.text("SITCON", BOLD, 15, INK2, x: sx + 10, baseline: sy + 22, kern: 2.5)
        for i in 0..<5 {
            let lv = 5 - i
            let bx = sx + 10 + CGFloat(i) * 30, by = sy + 34
            let on = lv == level
            c.rounded(c.r(bx, by, 26, 40), 2, fill: on ? LV[lv]! : rgb(0x14223c))
            c.text("\(lv)", HEAVY, 26, on ? INK : rgb(0x5f6c84), x: bx + 13, baseline: by + 30, align: 1)
        }
        let name = [5: "QUIET", 4: "GUARDED", 3: "ELEVATED", 2: "SEVERE"][level]!
        c.text(name, HEAVY, 22, level == 2 && !blinkOn ? rgb(0xff6b73) : INK, x: sx + 10, baseline: sy + 100, kern: 1)
    }

    // 2. Radar sweep (one turn every 2 s)
    (sx, sy) = cell(1, 0)
    screen(c, sx, sy, sw, sh, glow: rgb(0x1f6feb, 0.22)) { _ in
        let cx = sx + sw / 2, cy = sy + sh / 2, rad: CGFloat = 46
        ctx.setStrokeColor(rgb(0x3987e5, 0.55)); ctx.setLineWidth(1)
        for k in 1...3 { ctx.strokeEllipse(in: c.r(cx - rad * CGFloat(k) / 3, cy - rad * CGFloat(k) / 3, rad * 2 * CGFloat(k) / 3, rad * 2 * CGFloat(k) / 3)) }
        ctx.move(to: CGPoint(x: cx - rad, y: c.h - cy)); ctx.addLine(to: CGPoint(x: cx + rad, y: c.h - cy))
        ctx.move(to: CGPoint(x: cx, y: c.h - cy - rad)); ctx.addLine(to: CGPoint(x: cx, y: c.h - cy + rad)); ctx.strokePath()
        let angle = -t * Double.pi
        for k in 0..<18 {
            let a0 = angle + Double(k) * 0.045
            ctx.move(to: CGPoint(x: cx, y: c.h - cy))
            ctx.addArc(center: CGPoint(x: cx, y: c.h - cy), radius: rad, startAngle: CGFloat(a0), endAngle: CGFloat(a0 + 0.05), clockwise: false)
            ctx.closePath()
            ctx.setFillColor(rgb(0x6fd3ff, 0.30 * (1 - Double(k) / 18)))
            ctx.fillPath()
        }
        for (bx, by, phase) in [(0.55, -0.35, 0.2), (-0.45, 0.25, 1.1), (0.15, 0.6, 1.6)] as [(Double, Double, Double)] {
            let since = (t + phase).truncatingRemainder(dividingBy: 2.0)
            let a = max(0, 1 - since / 1.2)
            c.radial(cx + CGFloat(bx) * rad, cy + CGFloat(by) * rad, 9, rgb(0xff4057, 0.25 + 0.75 * a))
        }
    }

    // 3. Breach alert, blinking once a second
    (sx, sy) = cell(2, 0)
    screen(c, sx, sy, sw, sh, glow: rgb(0xff2d3d, blinkOn ? 0.42 : 0.14)) { inner in
        c.fill(inner, rgb(0x3a0610, blinkOn ? 1 : 0.6))
        if blinkOn {
            c.text("BREACH", HEAVY, 44, rgb(0xff4057), x: sx + sw / 2, baseline: sy + 62, kern: 1, align: 1)
            c.text("DETECTED", BOLD, 18, INK, x: sx + sw / 2, baseline: sy + 88, kern: 4, align: 1)
        } else {
            c.text("STAND BY", BOLD, 18, rgb(0xff8a92), x: sx + sw / 2, baseline: sy + 64, kern: 4, align: 1)
        }
    }

    // 4. Stacked bars breathing
    (sx, sy) = cell(0, 1)
    screen(c, sx, sy, sw, sh, glow: rgb(0x3987e5, 0.18)) { _ in
        let heights: [CGFloat] = [0.30, 0.42, 0.36, 0.55, 0.48, 0.62, 0.58, 0.74, 0.69, 0.92]
        for (i, base) in heights.enumerated() {
            let wave = 0.88 + 0.12 * sin(t * Double.pi + Double(i) * 0.7)
            let bh = (sh - 30) * base * CGFloat(wave)
            let bx = sx + 12 + CGFloat(i) * 15
            let bottom = sy + sh - 12
            c.fill(c.r(bx, bottom - bh, 10, bh * 0.62), BLUE)
            c.fill(c.r(bx, bottom - bh * 1.0, 10, bh * 0.36), ORANGE)
        }
        c.fill(c.r(sx + 8, sy + sh - 12, sw - 16, 1), rgb(0x8796ae, 0.6))
    }

    // 5. Scrolling CVE IDs (one full cycle every 8 s)
    (sx, sy) = cell(1, 1)
    screen(c, sx, sy, sw, sh, glow: rgb(0x6fd3ff, 0.16)) { _ in
        let lh: CGFloat = 15, total = lh * CGFloat(CVES.count)
        let offset = CGFloat(t / SECONDS) * total
        for k in 0..<(CVES.count * 2) {
            let yy = sy + 16 + CGFloat(k) * lh - offset
            if yy < sy - lh || yy > sy + sh + lh { continue }
            let hot = k % CVES.count == 0 || k % CVES.count == 2
            c.text(CVES[k % CVES.count], k % CVES.count < 2 ? MONOB : MONO, 10.5, hot ? rgb(0xff6b73) : rgb(0x9fd8ff), x: sx + 9, baseline: yy)
        }
    }

    // 6. World of dots with pings
    (sx, sy) = cell(2, 1)
    screen(c, sx, sy, sw, sh, glow: rgb(0x3987e5, 0.16)) { _ in
        for gxI in 0..<16 { for gyI in 0..<9 {
            let dx = sx + 10 + CGFloat(gxI) * 9.8, dy = sy + 12 + CGFloat(gyI) * 11
            let land = (sin(Double(gxI) * 0.9) + cos(Double(gyI) * 1.3 + Double(gxI) * 0.4)) > -0.2
            if land { c.fill(c.r(dx, dy, 2.4, 2.4), rgb(0x5f86c9, 0.8)) }
        } }
        var rnd = Rand(s: 7)
        for k in 0..<6 {
            let px = sx + 16 + CGFloat(rnd.next()) * (sw - 32), py = sy + 14 + CGFloat(rnd.next()) * (sh - 28)
            let ph = (t + Double(k) * 0.37).truncatingRemainder(dividingBy: 1.4) / 1.4
            ctx.setStrokeColor(rgb(0xff4057, 0.9 * (1 - ph))); ctx.setLineWidth(1.5)
            let rr = 3 + CGFloat(ph) * 14
            ctx.strokeEllipse(in: c.r(px - rr, py - rr, rr * 2, rr * 2))
            c.fill(c.r(px - 1.5, py - 1.5, 3, 3), rgb(0xff4057))
        }
    }

    // 7-9. Bottom row: trend line, KEV count, ransomware groups
    (sx, sy) = cell(0, 2)
    screen(c, sx, sy, sw, sh, glow: rgb(0xffc426, 0.12)) { _ in
        let pts: [CGFloat] = [0.20, 0.26, 0.22, 0.31, 0.28, 0.35, 0.33, 0.30, 0.41, 0.38, 0.52, 0.47, 0.66, 0.61, 0.84]
        ctx.setStrokeColor(YELLOW); ctx.setLineWidth(2)
        for (i, v) in pts.enumerated() {
            let px = sx + 10 + CGFloat(i) * (sw - 20) / CGFloat(pts.count - 1), py = sy + sh - 14 - v * (sh - 34)
            if i == 0 { ctx.move(to: CGPoint(x: px, y: c.h - py)) } else { ctx.addLine(to: CGPoint(x: px, y: c.h - py)) }
        }
        ctx.strokePath()
        let lx = sx + sw - 10, ly = sy + sh - 14 - pts.last! * (sh - 34)
        c.radial(lx, ly, 10 + CGFloat(blinkOn ? 4 : 0), rgb(0xffc426, 0.9))
        c.text("OVER TIME", BOLD, 12, INK2, x: sx + 10, baseline: sy + 18, kern: 2)
    }
    (sx, sy) = cell(1, 2)
    screen(c, sx, sy, sw, sh, glow: rgb(0xff4057, 0.14)) { _ in
        c.text("EXPLOITED CVEs", BOLD, 12, INK2, x: sx + 10, baseline: sy + 18, kern: 2)
        c.text("1,756", HEAVY, 46, INK, x: sx + 10, baseline: sy + 70)
        c.text("+2 TODAY", BOLD, 15, rgb(0xff6b73), x: sx + 10, baseline: sy + 92, kern: 1.5)
    }
    (sx, sy) = cell(2, 2)
    screen(c, sx, sy, sw, sh, glow: rgb(0xd95926, 0.14)) { _ in
        c.text("RANSOMWARE · 7D", BOLD, 12, INK2, x: sx + 10, baseline: sy + 18, kern: 2)
        for (i, (name, v)) in GROUPS.enumerated() {
            let yy = sy + 30 + CGFloat(i) * 15
            c.text(name, MONO, 9.5, INK2, x: sx + 10, baseline: yy + 8)
            let shimmer = 0.94 + 0.06 * sin(t * 2 * Double.pi / 2 + Double(i))
            c.fill(c.r(sx + 64, yy, (sw - 76) * v * CGFloat(shimmer), 8), ORANGE)
        }
    }

    // Desk and the person monitoring the situation (seen from behind, wearing a headset)
    c.fill(c.r(600, 448, 600, 120), rgb(0x040914))
    c.fill(c.r(600, 448, 600, 2), rgb(0x3987e5, 0.45))
    c.radial(905, 452, 260, rgb(0x6fd3ff, 0.10))
    let person = CGMutablePath()
    let base = c.h
    person.move(to: CGPoint(x: 770, y: base - 640))
    person.addCurve(to: CGPoint(x: 838, y: base - 512), control1: CGPoint(x: 776, y: base - 560), control2: CGPoint(x: 800, y: base - 522))
    person.addLine(to: CGPoint(x: 880, y: base - 500))
    person.addLine(to: CGPoint(x: 884, y: base - 474))
    person.addLine(to: CGPoint(x: 926, y: base - 474))
    person.addLine(to: CGPoint(x: 930, y: base - 500))
    person.addLine(to: CGPoint(x: 972, y: base - 512))
    person.addCurve(to: CGPoint(x: 1040, y: base - 640), control1: CGPoint(x: 1010, y: base - 522), control2: CGPoint(x: 1034, y: base - 560))
    person.closeSubpath()
    person.addEllipse(in: c.r(866, 388, 78, 94))
    ctx.addPath(person); ctx.setFillColor(rgb(0x02050c)); ctx.fillPath()
    ctx.addPath(person); ctx.setStrokeColor(rgb(0x6fd3ff, 0.35)); ctx.setLineWidth(2); ctx.strokePath()
    // headset band and ear cup
    ctx.setStrokeColor(rgb(0x1c2740)); ctx.setLineWidth(6)
    ctx.addArc(center: CGPoint(x: 905, y: base - 435), radius: 44, startAngle: CGFloat(Double.pi * 0.08), endAngle: CGFloat(Double.pi * 0.92), clockwise: false)
    ctx.strokePath()
    c.rounded(c.r(852, 426, 16, 30), 7, fill: rgb(0x1c2740), stroke: rgb(0x6fd3ff, 0.4), lw: 1.2)
    c.rounded(c.r(942, 426, 16, 30), 7, fill: rgb(0x1c2740), stroke: rgb(0x6fd3ff, 0.4), lw: 1.2)
    // chair back peeking out below the shoulders
    c.rounded(c.r(842, 556, 126, 90), 14, fill: rgb(0x0a1222), stroke: rgb(0x22314e), lw: 2)

    // Headline block
    let bugW: CGFloat = 76
    c.fill(c.r(56, 52, bugW, 30), RED)
    if blinkOn { ctx.setFillColor(INK); ctx.fillEllipse(in: c.r(67, 62, 10, 10)) }
    c.text("LIVE", HEAVY, 21, INK, x: 84, baseline: 75, kern: 2.5)
    c.text("THE SITUATION MONITOR", BOLD, 24, INK2, x: 56 + bugW + 14, baseline: 76, kern: 3)
    let lines = ["I AM", "MONITORING", "THE SITUATION."]
    var size: CGFloat = 120
    while size > 40 && lines.map({ c.width(c.line($0, HEAVY, size, INK)) }).max()! > 540 { size -= 2 }
    var baseline: CGFloat = 112 + size * 0.92
    for l in lines {
        c.text(l, HEAVY, size, INK, x: 52, baseline: baseline)
        baseline += size * 0.93
    }
    c.fill(c.r(56, baseline - size * 0.93 + 22, 120, 6), YELLOW)
    c.text("Live board of hacks, breaches, exploited", DEMI, 25, INK2, x: 56, baseline: baseline - size * 0.93 + 62)
    c.text("vulnerabilities and ransomware.", DEMI, 25, INK2, x: 56, baseline: baseline - size * 0.93 + 92)

    // Ticker: one full loop every 8 s
    let ty: CGFloat = 572
    c.fill(c.r(0, ty - 3, CGFloat(W), 3), RED)
    c.fill(c.r(0, ty, CGFloat(W), CGFloat(H) - ty), NAVY)
    let crawl = "EXPLOITED VULNERABILITIES   ●   RANSOMWARE CLAIMS   ●   BREACH DUMPS   ●   SUPPLY-CHAIN ATTACKS   ●   25 PUBLIC SOURCES   ●   UPDATED EVERY 30 MINUTES   ●   "
    let crawlLine = c.line(crawl, BOLD, 23, INK, kern: 1.5)
    let repeatW = c.width(crawlLine)
    let offset = CGFloat(t / SECONDS) * repeatW
    c.clip(c.r(166, ty, CGFloat(W) - 166 - 360 - 26, CGFloat(H) - ty)) {
        var x = 176 - offset
        while x < CGFloat(W) {
            ctx.textMatrix = .identity
            ctx.textPosition = CGPoint(x: x, y: c.h - (ty + 38))
            CTLineDraw(crawlLine, ctx)
            x += repeatW
        }
    }
    c.fill(c.r(0, ty, 150, CGFloat(H) - ty), RED)
    c.text("BREAKING", HEAVY, 25, INK, x: 75, baseline: ty + 39, kern: 2, align: 1)
    c.fill(c.r(CGFloat(W) - 360, ty, 360, CGFloat(H) - ty), YELLOW)
    c.text("THESITUATIONMONITOR.ORG", HEAVY, 23, rgb(0x1b1400), x: CGFloat(W) - 180, baseline: ty + 38, kern: 1, align: 1)
}

func drawIcon(_ c: Canvas, size: CGFloat) {
    c.rounded(c.r(0, 0, size, size), size * 0.18, fill: NAVY)
    c.fill(c.r(0, size * 0.74, size, size * 0.26), RED)
    c.text("SM", HEAVY, size * 0.52, INK, x: size / 2, baseline: size * 0.62, align: 1)
    c.fill(c.r(size * 0.14, size * 0.82, size * 0.10, size * 0.10), INK)
}

func bitmap(_ w: Int, _ h: Int) -> CGContext {
    CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: srgb,
              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
}

func writePNG(_ ctx: CGContext, _ path: String) {
    let dest = CGImageDestinationCreateWithURL(URL(fileURLWithPath: path) as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, ctx.makeImage()!, nil)
    CGImageDestinationFinalize(dest)
}

// Fail loudly if a face is missing instead of shipping a silent fallback.
for name in [HEAVY, BOLD, DEMI, MONO, MONOB] {
    let resolved = CTFontCopyPostScriptName(CTFontCreateWithName(name as CFString, 12, nil)) as String
    if resolved != name { fatalError("font \(name) resolved to \(resolved)") }
}

let card = bitmap(W, H)
drawScene(Canvas(ctx: card, h: CGFloat(H)), t: 3.3)
writePNG(card, out + "/og-card.png")
for (name, px) in [("favicon.png", 64), ("apple-touch-icon.png", 180)] {
    let icon = bitmap(px, px)
    drawIcon(Canvas(ctx: icon, h: CGFloat(px)), size: CGFloat(px))
    writePNG(icon, out + "/" + name)
}

let videoURL = URL(fileURLWithPath: out + "/og-video.mp4")
try? FileManager.default.removeItem(at: videoURL)
let writer = try! AVAssetWriter(outputURL: videoURL, fileType: .mp4)
writer.shouldOptimizeForNetworkUse = true
let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
    AVVideoCodecKey: AVVideoCodecType.h264, AVVideoWidthKey: W, AVVideoHeightKey: H,
    AVVideoCompressionPropertiesKey: [AVVideoAverageBitRateKey: 1_800_000, AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel,
                                      AVVideoMaxKeyFrameIntervalKey: FPS * 2],
])
input.expectsMediaDataInRealTime = false
let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: [
    kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA, kCVPixelBufferWidthKey as String: W, kCVPixelBufferHeightKey as String: H,
])
writer.add(input)
writer.startWriting()
writer.startSession(atSourceTime: .zero)
let frames = Int(SECONDS * Double(FPS))
for f in 0..<frames {
    while !input.isReadyForMoreMediaData { Thread.sleep(forTimeInterval: 0.002) }
    var pb: CVPixelBuffer?
    CVPixelBufferPoolCreatePixelBuffer(nil, adaptor.pixelBufferPool!, &pb)
    guard let buf = pb else { fatalError("no pixel buffer") }
    CVPixelBufferLockBaseAddress(buf, [])
    let ctx = CGContext(data: CVPixelBufferGetBaseAddress(buf), width: W, height: H, bitsPerComponent: 8,
                        bytesPerRow: CVPixelBufferGetBytesPerRow(buf), space: srgb,
                        bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)!
    drawScene(Canvas(ctx: ctx, h: CGFloat(H)), t: Double(f) / Double(FPS))
    CVPixelBufferUnlockBaseAddress(buf, [])
    adaptor.append(buf, withPresentationTime: CMTime(value: CMTimeValue(f), timescale: CMTimeScale(FPS)))
}
input.markAsFinished()
let done = DispatchSemaphore(value: 0)
writer.finishWriting { done.signal() }
done.wait()
if writer.status != .completed { fatalError("video failed: \(String(describing: writer.error))") }
print("wrote og-card.png, og-video.mp4 (\(frames) frames), favicon.png, apple-touch-icon.png to \(out)")
