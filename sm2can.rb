class Sm2can < Formula
  include Language::Python::Virtualenv

  desc "Open-source macOS/Linux driver for SM2 Pro J2534 CAN adapter"
  homepage "https://github.com/aldoguzman97/sm2can"
  url "https://files.pythonhosted.org/packages/source/s/sm2can/sm2can-0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"

  depends_on "libusb"
  depends_on "python@3.12"

  resource "pyusb" do
    url "https://files.pythonhosted.org/packages/source/p/pyusb/pyusb-1.2.1.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "python-can" do
    url "https://files.pythonhosted.org/packages/source/p/python-can/python-can-4.4.2.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "packaging" do
    url "https://files.pythonhosted.org/packages/source/p/packaging/packaging-24.1.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "typing_extensions" do
    url "https://files.pythonhosted.org/packages/source/t/typing_extensions/typing_extensions-4.12.2.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "wrapt" do
    url "https://files.pythonhosted.org/packages/source/w/wrapt/wrapt-1.16.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  resource "msgpack" do
    url "https://files.pythonhosted.org/packages/source/m/msgpack/msgpack-1.1.0.tar.gz"
    sha256 "PLACEHOLDER"
  end

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      SM2CAN installed. Quick start:

        sm2can probe              # Detect hardware
        sm2can monitor -b 500000  # Monitor CAN bus
        sm2can-capture guide      # USB capture instructions

      The SM2 Pro needs 12V on the OBD connector to boot.
      USB power alone is not sufficient for CAN communication.
    EOS
  end

  test do
    assert_match "sm2can", shell_output("#{bin}/sm2can --version")
  end
end
