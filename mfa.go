package main

import (
	"errors"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"mywhoosh2garmin/garmin"
)

// promptGarminMFA is called by the login worker, never by the UI goroutine.
// Only the worker waits for a result, so the dialog remains responsive.
func promptGarminMFA(parent fyne.Window, message string) (string, error) {
	type result struct {
		code string
		err  error
	}
	results := make(chan result, 1)
	fyne.Do(func() {
		newMFADialog(parent, message, func(code string, err error) {
			results <- result{code, err}
		}).Show()
	})
	r := <-results
	return r.code, r.err
}

func newMFADialog(parent fyne.Window, message string, complete func(string, error)) *dialog.FormDialog {
	var once sync.Once
	code := widget.NewEntry()
	code.SetPlaceHolder("Verification code")
	code.Validator = func(value string) error {
		if strings.TrimSpace(value) == "" {
			return errors.New("Enter the verification code")
		}
		return nil
	}
	item := widget.NewFormItem("Code", code)
	instructions := widget.NewLabel(message)
	instructions.Wrapping = fyne.TextWrapWord
	d := dialog.NewForm("Garmin two-factor authentication", "Verify", "Cancel",
		[]*widget.FormItem{widget.NewFormItem("", instructions), item}, func(ok bool) {
			once.Do(func() {
				value := strings.TrimSpace(code.Text)
				code.SetText("")
				if !ok {
					complete("", garmin.ErrMFACancelled)
					return
				}
				complete(value, nil)
			})
		}, parent)
	code.OnSubmitted = func(string) { d.Submit() }
	d.Resize(fyne.NewSize(480, 220))
	return d
}
