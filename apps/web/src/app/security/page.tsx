import OperationsModule from "@/components/operations-module";
import MfaEnrollment from "@/components/mfa-enrollment";

export default function Page() {
  return (
    <>
      <OperationsModule module="security"/>
      <div className="mx-auto max-w-[1500px] px-5 pb-10">
        <MfaEnrollment/>
      </div>
    </>
  );
}
