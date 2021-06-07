Pod::Spec.new do |s|
    # General information
    s.cocoapods_version = '>= 1.10'
    s.name              = 'PowerAuthCore'
    s.version           = '%DEPLOY_VERSION%'
    s.summary           = 'PowerAuthCore library for Apple platforms'
    s.homepage          = 'https://github.com/wultra/powerauth-client-core'
    s.social_media_url  = 'https://twitter.com/wultra'
    s.documentation_url = 'https://github.com/wultra/powerauth-client-core/blob/develop/docs/Readme.md'
    s.author            = { 
        'Wultra s.r.o.' => 'support@wultra.com'
    }
    s.license = { 
        :type => 'Apache License, Version 2.0', 
        :file => 'LICENSE' 
    }
        
    # Source files
    s.source = { 
        :git => 'https://github.com/wultra/powerauth-client-core.git',
        :tag => "#{s.version}",
        :submodules => true
    }
    
    s.ios.deployment_target  = '9.0'
    s.tvos.deployment_target = '9.0'
    s.osx.deployment_target = '10.15'
    
    # XCFramework  build
    s.prepare_command = './scripts/ios-build-core.sh --out-dir Build/PowerAuthCore'

    # Produced files
    s.vendored_frameworks   = 'Build/PowerAuthCore/PowerAuthCore.xcframework'

end
