{  
   'targets':[  
      {  
         'conditions':[  
            [  
               'target_arch=="x86"',
               {  
                  'target_name':'windivert',
                  'sources':['windivert.cc'],
                  'libraries':[  
                     "../windivertlib/x86/windivert.lib"
                  ],
                  'copies':[  
                     {  
                        'destination':'build/Release',
                        'files':[  
                           'windivertlib/x86/WinDivert32.sys',
                           'windivertlib/x86/WinDivert.dll'
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
						"../windivertlib/x64/windivert.lib"
                  ],
                  'copies':[  
                     {  
                        'destination':'build/Release',
                        'files':[  
                           'windivertlib/x64/WinDivert64.sys',
                           'windivertlib/x64/WinDivert.dll'
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