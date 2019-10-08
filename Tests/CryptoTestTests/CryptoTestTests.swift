import XCTest
@testable import CryptoTest

final class CryptoTestTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(CryptoTest().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
