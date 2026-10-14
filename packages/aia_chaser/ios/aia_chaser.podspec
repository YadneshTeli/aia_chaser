Pod::Spec.new do |s|
  s.name             = 'aia_chaser'
  s.version          = '0.1.0-alpha.1'
  s.summary          = 'AIA Chaser iOS plugin implementation.'
  s.description      = <<-DESC
Automatically chases missing intermediate SSL/TLS certificates via AIA, validates full chains with system trust, and fixes handshake failures in Flutter.
                       DESC
  s.homepage         = 'https://github.com/aiachaser/aia_chaser'
  s.license          = { :type => 'BSD', :file => '../LICENSE' }
  s.author           = { 'AIA Chaser Authors' => 'security@aiachaser.dev' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '12.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
