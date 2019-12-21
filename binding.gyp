{  
   'targets':[  
      {  
         'conditions':[  
            [  
               'target_arch=="ia32"',
               {  
                  'target_name':'windivert',
                  'sources':['windivert.cc'],
                  'libraries':[  
                     "../bin/x64/windivert.lib"
                  ],
                  'copies':[  
                     {  
                        'destination':'build/Release',
                        'files':[  
                           'bin/x86/WinDivert64.sys',
                           'bin/x86/WinDivert.dll'
                        ]
                     }
                  ],
				  "msbuild_settings": {
						"Link": {
							"ImageHasSafeExceptionHandlers": "false"
						}
					},
					"cflags!": [ "-fno-exceptions" ],
				"cflags_cc!": [ "-fno-exceptions" ],
				"include_dirs": [
				"<!@(node -p \"require('node-addon-api').include\")"
				],
				'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
               }
            ],
            [  
               'target_arch=="x64"',
               {  
                  'target_name':'windivert',
                  'sources':[  
                     'windivert.cc'
                  ],
                  'libraries':[
						"../bin/x64/windivert.lib"
                  ],
                  'copies':[  
                     {  
                        'destination':'build/Release',
                        'files':[  
                           'bin/x64/WinDivert64.sys',
                           'bin/x64/WinDivert.dll'
                        ]
                     }
                  ],
				"cflags!": [ "-fno-exceptions" ],
				"cflags_cc!": [ "-fno-exceptions" ],
				"include_dirs": [
				"<!@(node -p \"require('node-addon-api').include\")"
				],
				'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
               }
            ]
         ]
      }
   ]
}