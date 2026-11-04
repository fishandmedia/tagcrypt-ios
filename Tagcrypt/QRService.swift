import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import VisionKit

enum TagcryptQRCodec {
    private static let prefix = "TAGCRYPT1:"
    static let maximumPayloadBytes = 1_200 // Conservative paper-scanning cap; printable at 60 mm or larger

    static func encode(_ record: Data) -> String {
        prefix + record.base64EncodedString()
    }

    static func decode(_ value: String) throws -> Data {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix),
              let data = Data(base64Encoded: String(trimmed.dropFirst(prefix.count))),
              VaultCrypto.isTagcryptRecord(data) else {
            throw VaultError.malformedRecord
        }
        return data
    }

    static func image(for value: String, correctionLevel: String = "Q") -> UIImage? {
        guard value.utf8.count <= maximumPayloadBytes else { return nil }
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = correctionLevel
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        guard let cgImage = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        // Flatten the Core Image output onto opaque white. This keeps the code
        // visible in SwiftUI previews, Photos, printers, and exported PNGs.
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: cgImage.width, height: cgImage.height))
        return renderer.image { context in
            let bounds = CGRect(x: 0, y: 0, width: cgImage.width, height: cgImage.height)
            UIColor.white.setFill()
            context.fill(bounds)
            UIImage(cgImage: cgImage).draw(in: bounds)
        }
    }
}

struct TagcryptQRDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.png] }
    let data: Data

    init(image: UIImage) {
        data = image.pngData() ?? Data()
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct TagcryptQRShareSheet: UIViewControllerRepresentable {
    let image: UIImage

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [image], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) { }
}

struct TagcryptQRScanner: UIViewControllerRepresentable {
    let onResult: (String) -> Void
    let onFailure: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeCoordinator() -> Coordinator { Coordinator(onResult: onResult, onFailure: onFailure, dismiss: dismiss) }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true
        )
        controller.delegate = context.coordinator
        if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
            try? controller.startScanning()
        } else {
            DispatchQueue.main.async { onFailure("Live QR scanning is not available on this device. Use an iPhone with a supported camera and iOS version.") }
        }
        return controller
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) { }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onResult: (String) -> Void
        private let onFailure: (String) -> Void
        private let dismiss: DismissAction
        private var delivered = false

        init(onResult: @escaping (String) -> Void, onFailure: @escaping (String) -> Void, dismiss: DismissAction) {
            self.onResult = onResult
            self.onFailure = onFailure
            self.dismiss = dismiss
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            deliver(from: addedItems)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didUpdate updatedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            deliver(from: updatedItems)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            onFailure("QR scanner unavailable: \(error.localizedDescription)")
        }

        private func deliver(from items: [RecognizedItem]) {
            guard !delivered,
                  let value = items.compactMap({ item -> String? in
                      guard case let .barcode(barcode) = item else { return nil }
                      return barcode.payloadStringValue
                  }).first else { return }
            delivered = true
            dismiss()
            onResult(value)
        }
    }
}
