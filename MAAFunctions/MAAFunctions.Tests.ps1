#region
Remove-Module MAAFunctions
Import-Module .\MAAFunctions\MAAFunctions.psm1
#endregion

#region Clear-Spaces
Describe 'Clear-Spaces Tests' {
	Context 'Test spaces clears' {
		It 'Should clear leading space' {Clear-Spaces " Test string" | Should -Be "Test string"}
		It 'Should clear leading spaces' {Clear-Spaces "     Test string" | Should -Be "Test string"}
		It 'Should clear ending space' {Clear-Spaces "Test string " | Should -Be "Test string"}
		It 'Should clear ending spaces' {Clear-Spaces "Test string   " | Should -Be "Test string"}
	}

	Context 'Test clear spaces from pipeline' {
		It 'Clear leading spaces from pipeline' {"  Test string" | Clear-Spaces | Should -Be "Test string"}
		It 'Clear ending spaces from pipeline' {"Test string    " | Clear-Spaces | Should -Be "Test string"}
		It 'Clear leading and ending space from pipeline' {" Test string " | Clear-Spaces | Should -Be "Test string"}
	}
}
#endregion Slear-Spaces