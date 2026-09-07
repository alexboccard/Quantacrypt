import SwiftUI

struct EncryptView: View {
    @Bindable var model: EncryptModel
    @Environment(AppState.self) private var state

    var body: some View {
        Form {
            sourceSection
            protectionSection
            if model.sourcePath != nil {
                outputSection
            }
            actionSection
            activitySection
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Encrypt file", systemImage: "lock", action: model.encrypt)
                    // Not `.borderedProminent`: macOS 26 renders a disabled
                    // prominent toolbar button at full saturation, so it reads
                    // as live. The prominent copy is the inline one, which
                    // dims correctly.
                    .labelStyle(.titleAndIcon)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!model.canRun)
                    .help(model.validationMessage ?? "Encrypt with the chosen protection (⌘↩)")
            }
        }
        .alert("That file is already encrypted",
               isPresented: Binding(get: { model.wrongSection != nil },
                                    set: { if !$0 { model.wrongSection = nil } }),
               presenting: model.wrongSection) { target in
            Button("Open in \(target.section.title)") {
                model.wrongSection = nil
                state.open(URL(fileURLWithPath: target.path))
            }
            Button("Cancel", role: .cancel) { model.wrongSection = nil }
        } message: { target in
            Text("\(Format.fileName(target.path)) is a QuantaCrypt file. Encrypting it again would just wrap it in a second layer. You probably want to open it instead.")
        }
        // The outcome lands far below the button that was pressed; without
        // this a VoiceOver user gets silence and has to go hunting for it.
        .onChange(of: outcome) { _, new in
            if let new { AccessibilityNotification.Announcement(new).post() }
        }
        .sheet(item: $model.sharesToShow) { presentation in
            SharesSheet(shares: presentation.shares, context: presentation.context,
                        onSaved: { model.sharesSaved = true })
        }
        .confirmationDialog("Replace the existing file?", isPresented: $model.confirmReplace, titleVisibility: .visible) {
            Button("Replace file", role: .destructive, action: model.encryptReplacingExisting)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(model.outputPath.map(Format.fileName) ?? "The file") already exists and will be overwritten.")
        }
    }

    private var sourceSection: some View {
        Section("File") {
            if let path = model.sourcePath {
                PathRow(path: path, detail: model.sourceDetail,
                        systemImage: model.sourceIsFolder ? "folder" : "doc",
                        changeTitle: "Change…", changeLabel: "Change the file to encrypt",
                        onChange: model.chooseSource)
            } else {
                DropZone(title: "Drop a file or folder here",
                         subtitle: "Folders are zipped first, then encrypted as one file.",
                         systemImage: "arrow.down.doc",
                         chooseTitle: "Choose file or folder…",
                         onChoose: model.chooseSource,
                         accepts: EncryptModel.acceptsDrop,
                         onDrop: { model.setSource($0.path) })
            }
        }
    }

    private var protectionSection: some View {
        Section("Protection") {
            Picker("Protect with", selection: $model.mode) {
                ForEach(ProtectionMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            // The choice has to be explicable *before* it is made: switching
            // to Split key to find out what it is produces three QCSHARE-
            // blobs and a sheet that will not close until files are saved.
            Text(model.mode == .password
                 ? "One password opens the file. Anyone who has it can open the file; nobody who doesn't, can."
                 : "The key is split into shares handed to different people. You choose how many of them are needed to open the file; fewer than that cannot.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            switch model.mode {
            case .password:
                NewPasswordFields(password: $model.password, confirmation: $model.confirmation,
                                  onSubmit: model.encrypt)
                WarningStrip(text: "If you forget this password the file is gone. QuantaCrypt cannot recover it, and neither can anyone else.")
            case .splitKey:
                SplitKeyFields(threshold: $model.threshold, total: $model.total)
            }
        }
    }

    private var outputSection: some View {
        Section("Save to") {
            if let output = model.outputPath {
                PathRow(path: output, detail: nil, systemImage: "doc.badge.plus",
                        changeTitle: "Change…", changeLabel: "Change where the encrypted file is saved",
                        onChange: model.chooseOutput)
            }
        }
    }

    @ViewBuilder
    private var actionSection: some View {
        if !model.isRunning {
            Section {
                PrimaryActionRow(title: "Encrypt file", systemImage: "lock",
                                 isEnabled: model.canRun, blockedReason: model.validationMessage,
                                 action: model.encrypt)
            }
        }
    }

    @ViewBuilder
    private var activitySection: some View {
        if model.isRunning || model.error != nil || model.status != nil || model.result != nil {
            Section {
                if model.isRunning {
                    ProgressPanel(progress: model.progress, isCancelling: model.isCancelling,
                                  onCancel: model.cancel)
                }
                if let error = model.error {
                    ErrorPanel(error: error)
                }
                if let status = model.status {
                    StatusNote(text: status)
                }
                if let result = model.result {
                    resultCard(result)
                }
            }
        }
    }

    private func resultCard(_ result: EncryptResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Encrypted \(result.filename)")
                        .font(.headline)
                    Text("\(Format.bytes(result.size)) · \(Format.tildePath(result.output))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }
            } icon: {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
            if result.mode == "shamir", let k = result.threshold, let n = result.total {
                Text("Any \(k) of the \(n) shares unlock it. Check it opens with \(k) shares before you hand them out.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // Links are never packed (they would point outside the archive);
            // the one front end that stayed silent about it was this one.
            if let skipped = result.skippedSymlinks, !skipped.isEmpty {
                Label("\(skipped.count) linked item\(skipped.count == 1 ? " was" : "s were") not included — links are never packed: \(skipped.joined(separator: ", "))",
                      systemImage: "link")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .lineLimit(4)
                    .accessibilityLabel("\(skipped.count) linked items were not included")
            }
            // The original is still sitting there in plain text. Saying so is
            // the difference between "I encrypted my file" and the truth.
            if let source = model.sourcePath {
                Label("The original \(Format.fileName(source)) is untouched, still readable, in \(Format.tildePath(Format.directory(source))).",
                      systemImage: "doc.text")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                // Verify writes nothing, so this is a safe thing to press —
                // and the only way to learn the password works while it is
                // still fresh in mind.
                Button("Check it opens") { state.verifyEncrypted(result.output) }
                Button("Show in Finder") { Finder.reveal(result.output) }
                // Gone once "Check it opens" has verified the file: the
                // shares are dropped from the model at that point.
                if result.mode == "shamir", result.shares != nil {
                    Button("Show shares again") {
                        model.sharesToShow = result.makeSharesPresentation()
                    }
                }
                Button("Encrypt another file", action: model.reset)
            }
        }
        .padding(.vertical, 4)
    }

    private var outcome: String? {
        if let error = model.error { return error.message }
        if let result = model.result { return "Encrypted \(result.filename)." }
        return nil
    }
}
