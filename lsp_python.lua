local lspconfig = require 'lspconfig'

lspconfig.pyright.setup{
	cmd = {"pyright-langserver", "--stdio"};
	filetypes = {"python"};
	root_dir = lspconfig.util.root_pattern(".git", "setup.py",  "setup.cfg", "pyproject.toml", "requirements.txt");
	settings = {
		python = {
			analysis = {
				autoSearchPaths= true;
				diagnosticMode = 'workspace';
				typeCheckingMode = 'strict';
			};
		};
		pyright = {
			useLibraryCodeForTypes = true;
			disableOrganizeImports = true;
		};
	};
	-- -- The following before_init function can be removed once https://github.com/neovim/neovim/pull/12638 is merged
	-- before_init = function(initialize_params)
	-- 	initialize_params['workspaceFolders'] = {{
	-- 		name = 'workspace',
	-- 		uri = initialize_params['rootUri']
	-- 	}}
	-- end
}
