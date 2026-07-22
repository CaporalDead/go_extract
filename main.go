// Command go_extract : application graphique portable (Windows/macOS/Linux) pour
// déchiffrer une archive de réversibilité Monkey Factory.
//
// L'utilisateur choisit :
//   - le dossier contenant les fichiers reçus (<network>.zip.enc, .sig, .sign.pub),
//   - sa clé de déchiffrement K_i (collée, ou chargée depuis un fichier),
//   - le dossier où écrire l'archive en clair.
//
// L'application VÉRIFIE la signature d'origine (Ed25519) puis DÉCHIFFRE
// (secretstream XChaCha20-Poly1305). Elle affiche l'empreinte de la clé publique
// pour comparaison avec celle reçue par un second canal.
package main

import (
	"io"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/CaporalDead/go_extract/internal/rxcrypto"
)

type appUI struct {
	win fyne.Window

	kit         *rxcrypto.KitFiles
	fingerprint string

	srcEntry *widget.Entry
	keyEntry *widget.Entry
	outEntry *widget.Entry
	info     *widget.Label
	progress *widget.ProgressBarInfinite
	runBtn   *widget.Button
}

func main() {
	a := app.NewWithID("io.monkeyfactory.reversibilite.extract")
	w := a.NewWindow("Déchiffrement des archives de réversibilité — Monkey Factory")
	ui := &appUI{win: w}

	ui.srcEntry = widget.NewEntry()
	ui.srcEntry.SetPlaceHolder("Dossier contenant les fichiers reçus (.zip.enc, .sig, .sign.pub)")
	ui.srcEntry.Disable()
	srcBtn := widget.NewButton("Parcourir…", ui.chooseSource)

	ui.keyEntry = widget.NewEntry()
	ui.keyEntry.SetPlaceHolder("Clé de déchiffrement (hexadécimal)")
	keyBtn := widget.NewButton("Depuis un fichier…", ui.chooseKeyFile)

	ui.outEntry = widget.NewEntry()
	ui.outEntry.SetPlaceHolder("Dossier où écrire l'archive déchiffrée (.zip)")
	ui.outEntry.Disable()
	outBtn := widget.NewButton("Parcourir…", ui.chooseOutput)

	ui.info = widget.NewLabel("Choisissez d'abord le dossier des fichiers reçus.")
	ui.info.Wrapping = fyne.TextWrapWord

	ui.progress = widget.NewProgressBarInfinite()
	ui.progress.Hide()

	ui.runBtn = widget.NewButton("Vérifier la signature + déchiffrer", ui.run)
	ui.runBtn.Importance = widget.HighImportance

	form := container.NewVBox(
		widget.NewLabelWithStyle("1. Dossier des fichiers reçus", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, srcBtn, ui.srcEntry),
		widget.NewLabelWithStyle("2. Votre clé de déchiffrement", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, keyBtn, ui.keyEntry),
		widget.NewLabelWithStyle("3. Dossier de sortie", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, outBtn, ui.outEntry),
		widget.NewSeparator(),
		ui.info,
		ui.progress,
		ui.runBtn,
	)

	w.SetContent(container.NewPadded(form))
	w.Resize(fyne.NewSize(720, 460))
	w.CenterOnScreen()
	w.ShowAndRun()
}

func (ui *appUI) chooseSource() {
	dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
		if err != nil || u == nil {
			return
		}
		dir := u.Path()
		ui.srcEntry.SetText(dir)
		kit, err := rxcrypto.DetectKit(dir)
		if err != nil {
			ui.kit = nil
			ui.info.SetText("⚠ " + err.Error())
			return
		}
		if miss := kit.Missing(); len(miss) > 0 {
			ui.kit = nil
			ui.info.SetText("⚠ Fichier(s) manquant(s) : " + join(miss) +
				"\nAssurez-vous d'avoir téléchargé tous les fichiers dans le même dossier.")
			return
		}
		_, fp, err := rxcrypto.LoadPublicKey(kit.PubPath)
		if err != nil {
			ui.kit = nil
			ui.info.SetText("⚠ Clé publique illisible : " + err.Error())
			return
		}
		ui.kit = kit
		ui.fingerprint = fp
		// Pré-remplit le dossier de sortie avec le dossier source si vide.
		if ui.outEntry.Text == "" {
			ui.outEntry.SetText(dir)
		}
		ui.info.SetText("Réseau détecté : " + kit.Network +
			"\nEmpreinte de la clé publique : " + fp +
			"\n(Comparez-la à l'empreinte reçue par un autre canal avant de déchiffrer.)")
	}, ui.win)
}

func (ui *appUI) chooseKeyFile() {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			dialog.ShowError(err, ui.win)
			return
		}
		ui.keyEntry.SetText(trimSpace(string(data)))
	}, ui.win)
}

func (ui *appUI) chooseOutput() {
	dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
		if err != nil || u == nil {
			return
		}
		ui.outEntry.SetText(u.Path())
	}, ui.win)
}

func (ui *appUI) run() {
	if ui.kit == nil {
		dialog.ShowInformation("Étape manquante", "Choisissez d'abord un dossier source valide (fichiers reçus).", ui.win)
		return
	}
	key, err := rxcrypto.ParseKey(ui.keyEntry.Text)
	if err != nil {
		dialog.ShowError(err, ui.win)
		return
	}
	outDir := trimSpace(ui.outEntry.Text)
	if outDir == "" {
		dialog.ShowInformation("Étape manquante", "Choisissez un dossier de sortie.", ui.win)
		return
	}
	outPath := filepath.Join(outDir, ui.kit.Network+".zip")

	start := func() {
		ui.setBusy(true)
		go func() {
			verr := verifyAndDecrypt(ui.kit, key, outPath)
			fyne.Do(func() {
				ui.setBusy(false)
				if verr != nil {
					dialog.ShowError(verr, ui.win)
					return
				}
				dialog.ShowInformation("Déchiffrement réussi",
					"Signature d'origine VALIDE.\n\nArchive déchiffrée écrite dans :\n"+outPath, ui.win)
			})
		}()
	}

	if _, err := os.Stat(outPath); err == nil {
		dialog.ShowConfirm("Écraser le fichier ?",
			ui.kit.Network+".zip existe déjà dans ce dossier. Le remplacer ?",
			func(ok bool) {
				if ok {
					start()
				}
			}, ui.win)
		return
	}
	start()
}

func (ui *appUI) setBusy(b bool) {
	if b {
		ui.progress.Show()
		ui.progress.Start()
		ui.runBtn.Disable()
		ui.info.SetText("Traitement en cours… (la vérification et le déchiffrement peuvent prendre un moment sur les gros fichiers)")
	} else {
		ui.progress.Stop()
		ui.progress.Hide()
		ui.runBtn.Enable()
	}
}

// verifyAndDecrypt enchaîne vérification de signature puis déchiffrement.
func verifyAndDecrypt(kit *rxcrypto.KitFiles, key []byte, outPath string) error {
	pub, _, err := rxcrypto.LoadPublicKey(kit.PubPath)
	if err != nil {
		return err
	}
	if err := rxcrypto.VerifySignature(kit.EncPath, kit.SigPath, pub); err != nil {
		return err
	}
	if _, err := rxcrypto.Decrypt(kit.EncPath, outPath, key); err != nil {
		return err
	}
	return nil
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func trimSpace(s string) string {
	// évite d'importer strings pour un seul usage trivial côté UI
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
