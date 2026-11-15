package main

import (
	"errors"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"mywhoosh2garmin/garmin"
)

func TestMFADialog(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		name := "submit"
		if cancel {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			a := test.NewApp()
			defer a.Quit()
			w := a.NewWindow("test")
			defer w.Close()
			w.Resize(fyne.NewSize(720, 700))
			calls := 0
			var gotCode string
			var gotErr error
			d := newMFADialog(w, "Enter the Garmin code.", func(code string, err error) {
				calls++
				gotCode, gotErr = code, err
			})
			d.Show()
			popup := w.Canvas().Overlays().Top().(*widget.PopUp)
			var entry *widget.Entry
			var findEntry func(fyne.CanvasObject)
			findEntry = func(obj fyne.CanvasObject) {
				switch v := obj.(type) {
				case *fyne.Container:
					for _, child := range v.Objects {
						findEntry(child)
					}
				case *widget.Form:
					for _, item := range v.Items {
						findEntry(item.Widget)
					}
				case *widget.Entry:
					entry = v
				}
			}
			findEntry(popup.Content)
			if entry == nil {
				t.Fatal("no verification code field")
			}
			d.Submit()
			if calls != 0 {
				t.Fatal("blank code accepted")
			}
			entry.SetText(" \t ")
			d.Submit()
			if calls != 0 {
				t.Fatal("whitespace code accepted")
			}
			test.Type(entry, "012345 ")
			if cancel {
				d.Hide()
				if !errors.Is(gotErr, garmin.ErrMFACancelled) || gotCode != "" {
					t.Fatalf("cancel: code=%q, error=%v", gotCode, gotErr)
				}
			} else {
				d.Submit()
				if gotErr != nil || gotCode != "012345" {
					t.Fatalf("submit: code=%q, error=%v", gotCode, gotErr)
				}
			}
			if entry.Text != "" {
				t.Error("code not cleared after dialog closes")
			}
			d.Hide()
			if calls != 1 {
				t.Errorf("completion called %d times", calls)
			}
			if w.Canvas().Overlays().Top() != nil {
				t.Error("dialog still visible")
			}
		})
	}
}
